# Χρήστες, συνεδρίες και τεχνουργήματα διαπιστευτηρίων

{{#include ../../banners/hacktricks-training.md}}

Ξεκινήστε με την ταυτότητα στην οποία ανήκει το τρέχον shell και, στη συνέχεια, καταγράψτε άλλους χρήστες, ομάδες, ενεργές συνεδρίες και αποθηκευμένα διαπιστευτήρια. Η σελίδα [πραγματικού, ενεργού και αποθηκευμένου user ID](euid-ruid-suid.md) εξηγεί γιατί τα ενεργά δικαιώματα μιας διεργασίας μπορεί να διαφέρουν από τον λογαριασμό με τον οποίο έγινε η σύνδεση.

## Καταγραφή ταυτοτήτων και πρόσβασης βάσει ομάδων

```bash
id
getent passwd
getent group
whoami
stat -c '%A %U:%G %n' /etc/passwd /etc/shadow /etc/group
```

`getent` περιλαμβάνει λογαριασμούς από υπηρεσίες καταλόγου που μπορεί να μην εμφανίζονται με απλή ανάγνωση του `/etc/passwd`. Ελέγξτε λογαριασμούς με UID 0, login shells, home directories, supplementary groups και λογαριασμούς των οποίων οι ρυθμίσεις επιτρέπουν απροσδόκητα interactive login. Η σελίδα [interesting groups](interesting-groups-linux-pe/README.md) καλύπτει εκχωρημένη πρόσβαση όπως `sudo`, `docker`, `disk` και `shadow`. Ελέγξτε τα πραγματικά filesystem ACLs και την τοπική πολιτική προτού θεωρήσετε ένα όνομα group ένδειξη προνομίων.

Αν το [NSS αντιστοιχίζει τα ερωτήματα `passwd`, `group` ή `shadow`](https://man7.org/linux/man-pages/man5/nsswitch.conf.5.html) σε database, ελέγξτε τον ενεργό provider και τη διαδρομή των ρυθμίσεών του πριν αξιολογήσετε ταυτότητες που βασίζονται σε database. Σε εγκαταστάσεις PostgreSQL NSS, τα `/etc/nss-pgsql.conf` και `/etc/nss-pgsql-root.conf` αποτελούν μόνο ενδείξεις για διαδρομές, καθώς οι ρυθμίσεις σύνδεσης μπορεί να περιέχουν credentials. Ένας database role έχει σημασία μόνο αν μπορεί να αλλάξει εγγραφές που πράγματι επιστρέφει ο ενεργός NSS provider και αν ένας λογαριασμός μπορεί να κάνει authentication με αυτές. Ένα primary GID 0 παρέχει συμμετοχή στο root group, όχι UID 0· μια αντιστοίχιση στο sudo group απαιτεί έναν ενεργό [κανόνα ομάδας sudoers](https://man7.org/linux/man-pages/man5/sudoers.5.html) και τυχόν απαιτούμενο authentication. Η αντιστοίχιση σε UID 0 αποτελεί διαφορετικό όριο ταυτότητας. Μην εμφανίζετε connection strings και μην αλλάζετε εγγραφές λογαριασμών κατά το παθητικό enumeration.

Ελέγξτε επίσης τα αριθμητικά UID σε όλους τους τοπικούς λογαριασμούς. Δύο ονόματα στο [`/etc/passwd`](https://man7.org/linux/man-pages/man5/passwd.5.html) μπορεί να αναφέρονται στην ίδια Unix file identity, ενώ τα records authentication για το login τους μπορεί να διαφέρουν. Επομένως, ένα νεοπροστιθέμενο alias με κοινό, μη μηδενικό UID μπορεί, μετά από επιτυχημένο authentication, να δώσει πρόσβαση στα αρχεία ή τις διεργασίες άλλου χρήστη· δεν παρέχει root, εκτός αν το UID είναι 0 ή υπάρχει ξεχωριστή διαδρομή προνομίων. Τα κοινόχρηστα UID μπορεί να είναι σκόπιμα. Επαληθεύστε την πηγή του λογαριασμού (`/etc/passwd` έναντι NSS), το ιστορικό δημιουργίας, το shell και το home, την πραγματική πολιτική authentication και το αν οι λογαριασμοί έχουν εξουσιοδοτηθεί να μοιράζονται την ταυτότητα. Ένας έλεγχος μόνο τοπικών λογαριασμών για διπλότυπα δεν μπορεί να αποκλείσει ένα alias από υπηρεσία καταλόγου.

## Εντοπισμός ενεργών και πρόσφατων sessions

```bash
who -a
w
last -a | head
loginctl list-sessions 2>/dev/null
ps -eo user,pid,ppid,tty,cmd --sort=user | head -80
screen -ls 2>/dev/null
tmux ls 2>/dev/null
```

Ένα socket `screen` ή `tmux` μπορεί να εκθέσει ένα υπάρχον shell, αν τα δικαιώματά του επιτρέπουν στον τρέχοντα χρήστη να συνδεθεί. Ελέγξτε τον κάτοχο και τα δικαιώματα του socket πριν επιχειρήσετε πρόσβαση· η συνεδρία άλλου χρήστη δεν είναι αυτομάτως προσβάσιμη. Ενδέχεται επίσης να έχουν σημασία μια ενεργή χρονική σήμανση sudo ή ένα socket SSH agent, αλλά η επαναχρησιμοποίησή τους εξαρτάται από την ταυτότητα του χρήστη, τα δικαιώματα και την πολιτική. Για κατάχρηση προώθησης agent, δείτε το [SSH forwarding agent exploitation](ssh-forward-agent-exploitation.md).

Ένα [OpenSSH multiplex control socket](https://man.openbsd.org/ssh_config#ControlMaster) είναι διαφορετικό από το `SSH_AUTH_SOCK`: τα `ControlMaster` και `ControlPath` επιτρέπουν σε επόμενους SSH clients να μοιράζονται μια υπάρχουσα, πιστοποιημένη σύνδεση, ενώ το `ControlPersist` μπορεί να διατηρήσει διαθέσιμο το master μετά τη λήξη της πρώτης συνεδρίας. Ελέγξτε το `.ssh/config` του τρέχοντος χρήστη και τις διαδρομές socket μέσα στο `.ssh` σε μικρό βάθος, μαζί με τον κάτοχο και τα δικαιώματα. Το όνομα ενός socket από μόνο του δεν αποδεικνύει ότι το master είναι ενεργό, ότι ο τρέχων χρήστης μπορεί να συνδεθεί ή ποιον απομακρυσμένο λογαριασμό χρησιμοποιεί.

## Επισκόπηση τεχνουργημάτων χρήστη

```bash
find /home -maxdepth 3 -type f \( -name 'authorized_keys' -o -name 'id_*' -o -name '*history' -o -name '.netrc' -o -name '.git-credentials' \) -ls 2>/dev/null
find /home -maxdepth 3 -type f \( -name '.bashrc' -o -name '.profile' -o -name '.zshrc' \) -ls 2>/dev/null
printenv SSH_AUTH_SOCK KRB5CCNAME GNUPGHOME 2>/dev/null
```

Το ιστορικό του shell, τα αρχεία εκκίνησης, τα κλειδιά SSH, οι ρυθμίσεις εφαρμογών, τα keyring του GPG και οι cache του Kerberos μπορούν να αποκαλύψουν διαπιστευτήρια ή σημεία persistence με δικαίωμα εγγραφής. Ένα `authorized_keys` ή ένα αρχείο εκκίνησης shell με δικαίωμα εγγραφής για λογαριασμό με περισσότερα προνόμια χρειάζεται έλεγχο. Η [σελίδα post-exploitation](../post-exploitation/README.md) καλύπτει τη μετεγκατάσταση του GPG homedir και την αναζήτηση διαπιστευτηρίων· η σελίδα [Linux Active Directory](linux-active-directory.md) καλύπτει την επαναχρησιμοποίηση cache και keytab του Kerberos. Η [σελίδα PAM](../software-information/pam-pluggable-authentication-modules.md) εξηγεί τους κινδύνους των πολιτικών ελέγχου ταυτότητας.
{{#include ../../banners/hacktricks-training.md}}
