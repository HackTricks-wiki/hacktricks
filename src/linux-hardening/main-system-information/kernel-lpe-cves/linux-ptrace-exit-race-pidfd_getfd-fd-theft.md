# Linux ptrace exit-race `pidfd_getfd()` FD theft

{{#include ../../../banners/hacktricks-training.md}}

Ένα χρήσιμο **Linux kernel privesc pattern** είναι η μετατροπή ενός **ptrace authorization bug** σε **file descriptor theft** από μια privileged διεργασία.

Στη μελέτη περίπτωσης του Qualys για το `__ptrace_may_access()` (CVE-2026-46333), ο attacker εκμεταλλεύεται ένα race με μια **privileged διεργασία που τερματίζει ή απορρίπτει credentials** και χρησιμοποιεί το `pidfd_getfd()` για να αντιγράψει ένα FD στη διεργασία του attacker.<sup>[[1]](#references)[[2]](#references)</sup>

## Βασική ιδέα

Το `pidfd_getfd()` αντιγράφει ένα file descriptor από μια άλλη διεργασία, αλλά πρώτα ελέγχει permissions τύπου ptrace έναντι του target.<sup>[[3]](#references)</sup> Αν αυτή η authorization δοθεί εσφαλμένα κατά τη διάρκεια ενός **teardown window**, ένας unprivileged attacker μπορεί να αντιγράψει:

- FDs για **sensitive files** που έχουν ήδη ανοιχτεί από έναν privileged helper
- FDs για **authenticated IPC channels** που έχουν ήδη authorized ως root

Αυτό μετατρέπει ένα kernel-side authorization bug σε ένα πολύ πρακτικό userspace primitive.<sup>[[1]](#references)</sup>

## Γιατί το primitive είναι επικίνδυνο

Το attack **δεν χρειάζεται bug στον ίδιο τον privileged helper**. Ο helper αρκεί να κρατά προσωρινά κάτι πολύτιμο:

- `/etc/shadow`
- `/etc/ssh/*_key`
- μια privileged σύνδεση D-Bus / systemd
- οποιοδήποτε άλλο ήδη ανοιχτό secret ή authorized channel

Μόλις αντιγραφεί στη διεργασία του attacker, το duplicate αναφέρεται στο ίδιο open file description, επομένως οι επόμενες αναγνώσεις ή τα IPC requests χρησιμοποιούν το ήδη ανοιχτό FD αντί να ανοίξουν ξανά το αρχικό pathname ή να ξεκινήσουν μια νέα authentication flow.<sup>[[2]](#references)[[3]](#references)</sup>

## Pattern εκμετάλλευσης

1. Εντόπισε ένα **setuid / setgid / file-capability binary** ή έναν **root daemon** που ανοίγει sensitive files ή διατηρεί χρήσιμες IPC connections.<sup>[[2]](#references)</sup>
2. Απόκτησε μια σχέση που ικανοποιεί τα σχετικά ptrace policy checks για το target path (για παράδειγμα, να είσαι ο **parent** ενός spawned privileged child υπό permissive ρυθμίσεις YAMA).<sup>[[2]](#references)[[4]](#references)</sup>
3. Εκμεταλλεύσου το race με τη διεργασία ενώ **τερματίζει**, **απορρίπτει credentials** ή εισέρχεται με άλλο τρόπο σε μια κατάσταση όπου η ptrace access θα έπρεπε να έχει καταστεί unavailable.<sup>[[2]](#references)</sup>
4. Χρησιμοποίησε `pidfd_open()` + `pidfd_getfd()` για να αντιγράψεις το target FD κατά τη διάρκεια του στενού authorization window.<sup>[[2]](#references)[[3]](#references)[[5]](#references)</sup>
5. Επαναχρησιμοποίησε το stolen FD από το unprivileged context.<sup>[[2]](#references)</sup>
- Κάνε `read()` secrets από ένα privileged file descriptor
- Στείλε requests μέσω ενός stolen authenticated IPC channel για να λάβεις **root-side actions**

Ελάχιστη μορφή του primitive.<sup>[[1]](#references)[[3]](#references)[[5]](#references)</sup>
```c
int p = pidfd_open(victim_pid, 0);
int stolen = pidfd_getfd(p, victim_fd, 0);
/* use stolen with read()/write()/sendmsg()/ioctl() depending on target */
```
## Πρακτικοί στόχοι για audit

Δώστε προτεραιότητα σε binaries και daemons που, έστω και για λίγο, κάνουν ένα από τα εξής:<sup>[[1]](#references)[[2]](#references)</sup>

- ανοίγουν αρχεία μόνο για root πριν ολοκληρώσουν τις μεταβάσεις προνομίων
- συνδέονται στο **system bus** και διατηρούν ένα ήδη εξουσιοδοτημένο κανάλι
- μεταφέρουν privileged FDs μεταξύ helper boundaries
- εκτελούν εργασίες ευαίσθητες ως προς την ασφάλεια κατά το teardown που βρίσκεται κοντά στο `do_exit()`

Καλοί υποψήφιοι για hunting:<sup>[[1]](#references)</sup>

- helpers διαχείρισης κωδικών πρόσβασης / λογαριασμών
- SSH helpers
- helpers που διαμεσολαβούνται από PolicyKit / D-Bus
- root desktop daemons που εκθέτουν μεθόδους D-Bus

## Το YAMA ως exploit gate

Το `kernel.yama.ptrace_scope` είναι ένα σημαντικό πρακτικό gate για abuse της οικογένειας ptrace:<sup>[[3]](#references)[[4]](#references)</sup>

- `0`: κλασική συμπεριφορά ptrace για το ίδιο UID
- `1`: συνήθως επιτρέπει tracing από parent -> child, κάτι που μπορεί να διατηρεί προσβάσιμα ορισμένα public exploit paths
- `2`: απαιτεί `CAP_SYS_PTRACE` για πρόσβαση τύπου attach και αποκλείει το abuse του `pidfd_getfd()` από unprivileged χρήστες σε αυτό το path
- `3`: απενεργοποιεί πλήρως το ptrace attach μέχρι την επανεκκίνηση

Για αυτή την technique, το `ptrace_scope=2` είναι ένα ισχυρό **temporary mitigation**, επειδή διακόπτει το public `pidfd_getfd()` exploitation path με `-EPERM` για unprivileged χρήστες.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

## Ιδέες για Detection / review

Κατά τον έλεγχο privileged Linux software, αναζητήστε τους εξής συνδυασμούς:

- **privileged child process** + **attacker-controlled parent**.<sup>[[2]](#references)[[4]](#references)</sup>
- προσωρινή πρόσβαση σε **πολύτιμα ανοιχτά αρχεία**
- προσωρινή πρόσβαση σε **authenticated D-Bus/systemd channels**.<sup>[[2]](#references)</sup>
- αποφάσεις ασφαλείας που επαναχρησιμοποιούν **ptrace-style authorization** εκτός του κλασικού `ptrace(2)`
- kernel APIs που μπορούν να **duplicatе, inherit ή re-export** υπάρχοντα privileged FDs

Κατά τον έλεγχο του kernel, θεωρήστε υψηλού κινδύνου κάθε path που εκτελεί **ptrace-equivalent authorization** κατά το **task teardown**, ειδικά αν η επιτυχία παρέχει άμεση πρόσβαση στο `task->files` ή σε άλλους ήδη εξουσιοδοτημένους πόρους διεργασιών.<sup>[[2]](#references)</sup>

## References

- [1] [CVE-2026-46333: Local Root Privilege Escalation and Credential Disclosure in the Linux Kernel ptrace Path (Qualys)](https://blog.qualys.com/vulnerabilities-threat-research/2026/05/20/cve-2026-46333-local-root-privilege-escalation-and-credential-disclosure-in-the-linux-kernel-ptrace-path)
- [2] [Κείμενο TXT του advisory της Qualys](https://cdn2.qualys.com/advisory/2026/05/20/cve-2026-46333-ptrace.txt)
- [3] [Σελίδα manual του pidfd_getfd(2)](https://man7.org/linux/man-pages/man2/pidfd_getfd.2.html)
- [4] [Τεκμηρίωση Yama του Linux kernel](https://www.kernel.org/doc/html/latest/admin-guide/LSM/Yama.html)
- [5] [Σελίδα manual του pidfd_open(2)](https://man7.org/linux/man-pages/man2/pidfd_open.2.html)
{{#include ../../../banners/hacktricks-training.md}}
