# Linux Active Directory

{{#include ../../banners/hacktricks-training.md}}

Ένα μηχάνημα linux μπορεί επίσης να είναι παρόν σε ένα περιβάλλον Active Directory.

Ένα μηχάνημα linux σε ένα AD μπορεί να **αποθηκεύει διάφορα CCACHE tickets μέσα σε αρχεία. Αυτά τα tickets μπορούν να χρησιμοποιηθούν και να καταχραστούν όπως οποιοδήποτε άλλο kerberos ticket**. Για να διαβάσετε αυτά τα tickets θα χρειαστεί να είστε ο χρήστης κάτοχος του ticket ή **root** μέσα στο μηχάνημα.

## Enumeration

### AD enumeration από linux

Αν έχετε πρόσβαση σε ένα AD σε linux (ή bash σε Windows) μπορείτε να δοκιμάσετε [https://github.com/lefayjey/linWinPwn](https://github.com/lefayjey/linWinPwn) για να καταγράψετε το AD.

Μπορείτε επίσης να ελέγξετε την παρακάτω σελίδα για να μάθετε **άλλους τρόπους για να καταγράψετε το AD από linux**:

{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

### FreeIPA

Το FreeIPA είναι μια ανοιχτού κώδικα **εναλλακτική** λύση για το Microsoft Windows **Active Directory**, κυρίως για **Unix** περιβάλλοντα. Συνδυάζει έναν πλήρη **LDAP κατάλογο** με ένα MIT **Kerberos** Key Distribution Center για διαχείριση παρόμοια με το Active Directory. Χρησιμοποιεί το Dogtag **Certificate System** για τη διαχείριση πιστοποιητικών CA & RA, υποστηρίζει **πολλαπλούς παράγοντες** αυθεντικοποίησης, συμπεριλαμβανομένων των smartcards. Το SSSD είναι ενσωματωμένο για διαδικασίες αυθεντικοποίησης Unix. Μάθετε περισσότερα γι' αυτό στην:

{{#ref}}
../freeipa-pentesting.md
{{#endref}}

## Παίζοντας με τα tickets

### Pass The Ticket

Σε αυτή τη σελίδα θα βρείτε διάφορες τοποθεσίες όπου μπορείτε να **βρείτε kerberos tickets μέσα σε έναν linux host**, στην επόμενη σελίδα μπορείτε να μάθετε πώς να μετατρέψετε αυτά τα CCache tickets σε μορφή Kirbi (τη μορφή που χρειάζεστε να χρησιμοποιήσετε σε Windows) και επίσης πώς να εκτελέσετε μια επίθεση PTT:

{{#ref}}
../../windows-hardening/active-directory-methodology/pass-the-ticket.md
{{#endref}}

### CCACHE ticket reuse από /tmp

Τα αρχεία CCACHE είναι δυαδικές μορφές για **αποθήκευση Kerberos credentials** και συνήθως αποθηκεύονται με δικαιώματα 600 στο `/tmp`. Αυτά τα αρχεία μπορούν να αναγνωριστούν από τη **μορφή ονόματος τους, `krb5cc_%{uid}`,** που σχετίζεται με το UID του χρήστη. Για την επαλήθευση του ticket αυθεντικοποίησης, η **μεταβλητή περιβάλλοντος `KRB5CCNAME`** θα πρέπει να ρυθμιστεί στη διαδρομή του επιθυμητού αρχείου ticket, επιτρέποντας την επαναχρησιμοποίησή του.

Λίστα με το τρέχον ticket που χρησιμοποιείται για αυθεντικοποίηση με `env | grep KRB5CCNAME`. Η μορφή είναι φορητή και το ticket μπορεί να **επανχρησιμοποιηθεί ρυθμίζοντας τη μεταβλητή περιβάλλοντος** με `export KRB5CCNAME=/tmp/ticket.ccache`. Η μορφή ονόματος του kerberos ticket είναι `krb5cc_%{uid}` όπου uid είναι το UID του χρήστη.
```bash
# Find tickets
ls /tmp/ | grep krb5cc
krb5cc_1000

# Prepare to use it
export KRB5CCNAME=/tmp/krb5cc_1000
```
### CCACHE ticket reuse from keyring

**Τα εισιτήρια Kerberos που αποθηκεύονται στη μνήμη μιας διαδικασίας μπορούν να εξαχθούν**, ιδιαίτερα όταν η προστασία ptrace της μηχανής είναι απενεργοποιημένη (`/proc/sys/kernel/yama/ptrace_scope`). Ένα χρήσιμο εργαλείο για αυτό το σκοπό βρίσκεται στο [https://github.com/TarlogicSecurity/tickey](https://github.com/TarlogicSecurity/tickey), το οποίο διευκολύνει την εξαγωγή με την ένεση σε συνεδρίες και την εκφόρτωση εισιτηρίων στο `/tmp`.

Για να ρυθμίσετε και να χρησιμοποιήσετε αυτό το εργαλείο, ακολουθούνται τα παρακάτω βήματα:
```bash
git clone https://github.com/TarlogicSecurity/tickey
cd tickey/tickey
make CONF=Release
/tmp/tickey -i
```
Αυτή η διαδικασία θα προσπαθήσει να εισάγει σε διάφορες συνεδρίες, υποδεικνύοντας επιτυχία αποθηκεύοντας τα εξαγόμενα εισιτήρια στο `/tmp` με μια ονοματολογία `__krb_UID.ccache`.

### CCACHE ticket reuse από SSSD KCM

Το SSSD διατηρεί ένα αντίγραφο της βάσης δεδομένων στη διαδρομή `/var/lib/sss/secrets/secrets.ldb`. Το αντίστοιχο κλειδί αποθηκεύεται ως κρυφό αρχείο στη διαδρομή `/var/lib/sss/secrets/.secrets.mkey`. Από προεπιλογή, το κλειδί είναι αναγνώσιμο μόνο αν έχετε δικαιώματα **root**.

Η κλήση του **`SSSDKCMExtractor`** με τις παραμέτρους --database και --key θα αναλύσει τη βάση δεδομένων και θα **αποκρυπτογραφήσει τα μυστικά**.
```bash
git clone https://github.com/fireeye/SSSDKCMExtractor
python3 SSSDKCMExtractor.py --database secrets.ldb --key secrets.mkey
```
Το **credential cache Kerberos blob μπορεί να μετατραπεί σε ένα χρησιμοποιήσιμο αρχείο Kerberos CCache** που μπορεί να περαστεί σε Mimikatz/Rubeus.

### CCACHE ticket reuse από keytab
```bash
git clone https://github.com/its-a-feature/KeytabParser
python KeytabParser.py /etc/krb5.keytab
klist -k /etc/krb5.keytab
```
### Εξαγωγή λογαριασμών από το /etc/krb5.keytab

Οι κωδικοί υπηρεσιών, που είναι απαραίτητοι για υπηρεσίες που λειτουργούν με δικαιώματα root, αποθηκεύονται με ασφάλεια στα αρχεία **`/etc/krb5.keytab`**. Αυτοί οι κωδικοί, παρόμοιοι με τους κωδικούς πρόσβασης για υπηρεσίες, απαιτούν αυστηρή εμπιστευτικότητα.

Για να ελέγξετε το περιεχόμενο του αρχείου keytab, μπορεί να χρησιμοποιηθεί το **`klist`**. Το εργαλείο έχει σχεδιαστεί για να εμφανίζει λεπτομέρειες κλειδιών, συμπεριλαμβανομένου του **NT Hash** για την αυθεντικοποίηση χρηστών, ιδιαίτερα όταν ο τύπος κλειδιού αναγνωρίζεται ως 23.
```bash
klist.exe -t -K -e -k FILE:C:/Path/to/your/krb5.keytab
# Output includes service principal details and the NT Hash
```
Για τους χρήστες Linux, **`KeyTabExtract`** προσφέρει λειτουργικότητα για την εξαγωγή του RC4 HMAC hash, το οποίο μπορεί να χρησιμοποιηθεί για την επαναχρησιμοποίηση του NTLM hash.
```bash
python3 keytabextract.py krb5.keytab
# Expected output varies based on hash availability
```
Στο macOS, **`bifrost`** χρησιμεύει ως εργαλείο για την ανάλυση αρχείων keytab.
```bash
./bifrost -action dump -source keytab -path /path/to/your/file
```
Χρησιμοποιώντας τις εξαγόμενες πληροφορίες λογαριασμού και κατακερματισμού, μπορούν να δημιουργηθούν συνδέσεις με διακομιστές χρησιμοποιώντας εργαλεία όπως το **`crackmapexec`**.
```bash
crackmapexec 10.XXX.XXX.XXX -u 'ServiceAccount$' -H "HashPlaceholder" -d "YourDOMAIN"
```
## Αναφορές

- [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [https://github.com/TarlogicSecurity/tickey](https://github.com/TarlogicSecurity/tickey)
- [https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#linux-active-directory](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#linux-active-directory)

{{#include ../../banners/hacktricks-training.md}}
