# Linux ptrace exit-race `pidfd_getfd()` κλοπή FD

{{#include ../../../banners/hacktricks-training.md}}

Ένα χρήσιμο **Linux kernel privesc pattern** είναι η μετατροπή ενός **ptrace authorization bug** σε **file descriptor theft** από μια privileged διεργασία.

Στο case study της Qualys για το `__ptrace_may_access()` (CVE-2026-46333), ο attacker ανταγωνίζεται χρονικά μια **privileged διεργασία που τερματίζεται ή αποβάλλει credentials** και χρησιμοποιεί το `pidfd_getfd()` για να αντιγράψει ένα FD στη διεργασία του attacker.

## Βασική ιδέα

Το `pidfd_getfd()` αντιγράφει ένα file descriptor από μια άλλη διεργασία, αλλά πρώτα ελέγχει permissions τύπου ptrace έναντι του target. Αν αυτή η authorization δοθεί εσφαλμένα κατά τη διάρκεια ενός **teardown window**, ένας unprivileged attacker μπορεί να αντιγράψει:

- FDs για **sensitive files** που έχουν ήδη ανοιχτεί από έναν privileged helper
- FDs για **authenticated IPC channels** που έχουν ήδη authorized ως root

Αυτό μετατρέπει ένα authorization bug στο kernel σε ένα πολύ πρακτικό userspace primitive.

## Γιατί το primitive είναι επικίνδυνο

Η επίθεση **δεν χρειάζεται bug στον ίδιο τον privileged helper**. Ο helper χρειάζεται μόνο να διατηρεί προσωρινά κάτι χρήσιμο:

- `/etc/shadow`
- `/etc/ssh/*_key`
- μια privileged σύνδεση D-Bus / systemd
- οποιοδήποτε άλλο ήδη ανοιχτό secret ή authorized channel

Μόλις αντιγραφεί στη διεργασία του attacker, ο kernel επιβάλλει τις operations στο **stolen FD**, όχι στο αρχικό pathname ή σε ένα νέο authentication flow.

## Exploitation pattern

1. Εντοπίστε ένα **setuid / setgid / file-capability binary** ή έναν **root daemon** που ανοίγει sensitive files ή διατηρεί χρήσιμες IPC connections.
2. Αποκτήστε μια σχέση που ικανοποιεί τα σχετικά ptrace policy checks για το target path (για παράδειγμα, να είστε ο **parent** ενός spawned privileged child υπό permissive ρυθμίσεις YAMA).
3. Κάντε race στη διεργασία ενώ **τερματίζεται**, **αποβάλλει credentials** ή εισέρχεται με άλλον τρόπο σε μια κατάσταση όπου η ptrace access θα έπρεπε να έχει καταστεί unavailable.
4. Χρησιμοποιήστε `pidfd_open()` + `pidfd_getfd()` για να αντιγράψετε το target FD κατά τη διάρκεια του σύντομου authorization window.
5. Επαναχρησιμοποιήστε το stolen FD από το unprivileged context:
- `read()` secrets από ένα privileged file descriptor
- στείλτε requests μέσω ενός stolen authenticated IPC channel για να εκτελεστούν **root-side actions**

Minimal primitive shape:
```c
int p = pidfd_open(victim_pid, 0);
int stolen = pidfd_getfd(p, victim_fd, 0);
/* use stolen with read()/write()/sendmsg()/ioctl() depending on target */
```
## Πρακτικοί στόχοι για έλεγχο

Δώστε προτεραιότητα σε binaries και daemons που, έστω και προσωρινά, κάνουν ένα από τα εξής:

- ανοίγουν αρχεία μόνο για root πριν ολοκληρώσουν τις μεταβάσεις προνομίων
- συνδέονται στο **system bus** και διατηρούν ένα ήδη εξουσιοδοτημένο κανάλι
- μεταφέρουν προνομιούχα FDs μεταξύ βοηθητικών διεργασιών
- εκτελούν εργασίες ευαίσθητες από άποψη ασφάλειας κατά τη διάρκεια teardown που βρίσκεται κοντά στο `do_exit()`

Καλοί υποψήφιοι για αναζήτηση:

- βοηθητικά προγράμματα διαχείρισης κωδικών πρόσβασης / λογαριασμών
- SSH helpers
- βοηθητικά προγράμματα που διαμεσολαβούνται μέσω PolicyKit / D-Bus
- root desktop daemons που εκθέτουν μεθόδους D-Bus

## Το YAMA ως exploit gate

Το `kernel.yama.ptrace_scope` αποτελεί σημαντικό πρακτικό gate για abuse της οικογένειας του ptrace:

- `0`: κλασική συμπεριφορά ptrace για το ίδιο UID
- `1`: συνήθως επιτρέπει tracing από parent -> child, διατηρώντας προσβάσιμα ορισμένα public exploit paths
- `2`: απαιτεί `CAP_SYS_PTRACE` για πρόσβαση τύπου attach και αποκλείει το abuse του `pidfd_getfd()` από unprivileged χρήστες σε αυτό το path
- `3`: απενεργοποιεί πλήρως το ptrace attach μέχρι το reboot

Για αυτή την τεχνική, το `ptrace_scope=2` αποτελεί ισχυρό **προσωρινό mitigation**, επειδή διακόπτει το public exploitation path του `pidfd_getfd()` επιστρέφοντας `-EPERM` σε unprivileged χρήστες.

## Ιδέες για Detection / review

Κατά τον έλεγχο privileged Linux software, αναζητήστε τους εξής συνδυασμούς:

- **privileged child process** + **attacker-controlled parent**
- προσωρινή πρόσβαση σε **πολύτιμα open files**
- προσωρινή πρόσβαση σε **authenticated D-Bus/systemd channels**
- αποφάσεις ασφάλειας που επαναχρησιμοποιούν **ptrace-style authorization** εκτός του κλασικού `ptrace(2)`
- kernel APIs που μπορούν να **duplicatе, inherit ή re-export** υπάρχοντα προνομιούχα FDs

Κατά τον έλεγχο του kernel, θεωρήστε κάθε path που εκτελεί **ptrace-equivalent authorization** κατά τη διάρκεια του **task teardown** ως υψηλού κινδύνου, ειδικά αν η επιτυχία παρέχει άμεση πρόσβαση στο `task->files` ή σε άλλους ήδη εξουσιοδοτημένους πόρους της διεργασίας.

## Παραπομπές

- [Qualys blog: CVE-2026-46333](https://blog.qualys.com/vulnerabilities-threat-research/2026/05/20/cve-2026-46333-local-root-privilege-escalation-and-credential-disclosure-in-the-linux-kernel-ptrace-path)
- [Qualys advisory TXT](https://cdn2.qualys.com/advisory/2026/05/20/cve-2026-46333-ptrace.txt)
- [pidfd_getfd(2) manual page](https://man7.org/linux/man-pages/man2/pidfd_getfd.2.html)
- [Linux kernel Yama documentation](https://www.kernel.org/doc/html/latest/admin-guide/LSM/Yama.html)

{{#include ../../../banners/hacktricks-training.md}}
