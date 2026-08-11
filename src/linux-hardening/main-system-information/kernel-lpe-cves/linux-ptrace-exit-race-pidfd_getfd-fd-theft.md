# Linux ptrace exit-race `pidfd_getfd()` κλοπή FD

Ένα χρήσιμο **Linux kernel privesc pattern** είναι η μετατροπή ενός **ptrace authorization bug** σε **file descriptor theft** από μια privileged process.

Στη μελέτη περίπτωσης της Qualys για το `__ptrace_may_access()` (CVE-2026-46333), ο attacker εκμεταλλεύεται ένα race με μια **privileged process που τερματίζει ή απορρίπτει credentials** και χρησιμοποιεί το `pidfd_getfd()` για να αντιγράψει ένα FD στη διεργασία του attacker.<sup>[[1]](#references)[[2]](#references)</sup>

## Core idea

Το `pidfd_getfd()` αντιγράφει ένα file descriptor από άλλη process, αλλά πρώτα ελέγχει permissions τύπου ptrace απέναντι στο target.<sup>[[3]](#references)</sup> Αν αυτή η authorization παραχωρηθεί εσφαλμένα κατά τη διάρκεια ενός **teardown window**, ένας unprivileged attacker μπορεί να αντιγράψει:

- FDs για **sensitive files** που έχουν ήδη ανοιχτεί από έναν privileged helper
- FDs για **authenticated IPC channels** που έχουν ήδη εξουσιοδοτηθεί ως root

Αυτό μετατρέπει ένα authorization bug στην πλευρά του kernel σε ένα πολύ πρακτικό userspace primitive.<sup>[[1]](#references)</sup>

## Why the primitive is dangerous

Η επίθεση **δεν** χρειάζεται bug στον ίδιο τον privileged helper. Ο helper πρέπει μόνο να διατηρεί προσωρινά κάτι πολύτιμο:

- `/etc/shadow`
- `/etc/ssh/*_key`
- μια privileged σύνδεση D-Bus / systemd
- οποιοδήποτε άλλο ήδη ανοιχτό secret ή authorized channel

Μόλις αντιγραφεί στη διεργασία του attacker, το αντίγραφο αναφέρεται στο ίδιο open file description, επομένως οι επόμενες αναγνώσεις ή IPC requests χρησιμοποιούν το ήδη ανοιχτό FD αντί να ανοίξουν ξανά το αρχικό pathname ή να ξεκινήσουν μια νέα authentication flow.<sup>[[2]](#references)[[3]](#references)</sup>

## Exploitation pattern

1. Εντοπίστε ένα **setuid / setgid / file-capability binary** ή έναν **root daemon** που ανοίγει sensitive files ή διατηρεί χρήσιμες IPC connections.<sup>[[2]](#references)</sup>
2. Αποκτήστε μια σχέση που ικανοποιεί τα σχετικά ptrace policy checks για το target path (για παράδειγμα, όντας ο **parent** ενός spawned privileged child υπό permissive ρυθμίσεις YAMA).<sup>[[2]](#references)[[4]](#references)</sup>
3. Εκμεταλλευτείτε το race με τη process ενώ **τερματίζει**, **απορρίπτει credentials** ή εισέρχεται με άλλο τρόπο σε κατάσταση όπου η ptrace access θα έπρεπε να έχει καταστεί unavailable.<sup>[[2]](#references)</sup>
4. Χρησιμοποιήστε `pidfd_open()` + `pidfd_getfd()` για να αντιγράψετε το target FD κατά τη διάρκεια του στενού authorization window.<sup>[[2]](#references)[[3]](#references)[[5]](#references)</sup>
5. Επαναχρησιμοποιήστε το stolen FD από το unprivileged context.<sup>[[2]](#references)</sup>
- `read()` secrets από ένα privileged file descriptor
- στείλτε requests μέσω ενός stolen authenticated IPC channel για να εκτελεστούν **root-side actions**

Minimal primitive shape.<sup>[[1]](#references)[[3]](#references)[[5]](#references)</sup>
```c
int p = pidfd_open(victim_pid, 0);
int stolen = pidfd_getfd(p, victim_fd, 0);
/* use stolen with read()/write()/sendmsg()/ioctl() depending on target */
```
## Πρακτικοί στόχοι για έλεγχο

Δώστε προτεραιότητα σε binaries και daemons που, έστω και προσωρινά, κάνουν ένα από τα εξής:<sup>[[1]](#references)[[2]](#references)</sup>

- ανοίγουν αρχεία που είναι διαθέσιμα μόνο στον root πριν ολοκληρώσουν τις μεταβάσεις προνομίων
- συνδέονται στο **system bus** και διατηρούν ένα κανάλι για το οποίο έχει ήδη γίνει authorization
- μεταφέρουν privileged FDs μεταξύ helper boundaries
- εκτελούν security-sensitive εργασίες κατά τη διάρκεια teardown που βρίσκεται κοντά στο `do_exit()`

Καλοί υποψήφιοι για έλεγχο:<sup>[[1]](#references)</sup>

- helpers για password / account management
- SSH helpers
- PolicyKit / D-Bus mediated helpers
- root desktop daemons που εκθέτουν D-Bus methods

## YAMA ως exploit gate

Το `kernel.yama.ptrace_scope` αποτελεί σημαντικό πρακτικό gate για abuse της οικογένειας ptrace:<sup>[[3]](#references)[[4]](#references)</sup>

- `0`: κλασική συμπεριφορά ptrace μεταξύ του ίδιου UID
- `1`: συνήθως επιτρέπει tracing από parent -> child, κάτι που μπορεί να διατηρεί προσβάσιμα ορισμένα public exploit paths
- `2`: απαιτεί `CAP_SYS_PTRACE` για attach-style πρόσβαση και αποκλείει το unprivileged `pidfd_getfd()` abuse σε αυτό το path
- `3`: απενεργοποιεί πλήρως το ptrace attach μέχρι το reboot

Για αυτή την τεχνική, το `ptrace_scope=2` αποτελεί ισχυρό **temporary mitigation**, επειδή διακόπτει το public `pidfd_getfd()` exploitation path με `-EPERM` για unprivileged users.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

## Ιδέες για detection / review

Κατά τον έλεγχο privileged Linux software, αναζητήστε τους εξής συνδυασμούς:

- **privileged child process** + **attacker-controlled parent**.<sup>[[2]](#references)[[4]](#references)</sup>
- προσωρινή πρόσβαση σε **valuable open files**
- προσωρινή πρόσβαση σε **authenticated D-Bus/systemd channels**.<sup>[[2]](#references)</sup>
- security decisions που επαναχρησιμοποιούν **ptrace-style authorization** εκτός του κλασικού `ptrace(2)`
- kernel APIs που μπορούν να **duplicate, inherit, ή re-export** υπάρχοντα privileged FDs

Κατά τον έλεγχο του kernel, θεωρήστε υψηλού κινδύνου κάθε path που εκτελεί **ptrace-equivalent authorization** κατά τη διάρκεια **task teardown**, ειδικά αν η επιτυχία παρέχει άμεση πρόσβαση στο `task->files` ή σε άλλους process resources για τους οποίους έχει ήδη γίνει authorization.<sup>[[2]](#references)</sup>

## References

- [1] [CVE-2026-46333: Τοπική κλιμάκωση προνομίων root και αποκάλυψη credentials στο Linux kernel ptrace path (Qualys)](https://blog.qualys.com/vulnerabilities-threat-research/2026/05/20/cve-2026-46333-local-root-privilege-escalation-and-credential-disclosure-in-the-linux-kernel-ptrace-path)
- [2] [TXT advisory της Qualys](https://cdn2.qualys.com/advisory/2026/05/20/cve-2026-46333-ptrace.txt)
- [3] [Σελίδα manual του pidfd_getfd(2)](https://man7.org/linux/man-pages/man2/pidfd_getfd.2.html)
- [4] [Τεκμηρίωση του Linux kernel Yama](https://www.kernel.org/doc/html/latest/admin-guide/LSM/Yama.html)
- [5] [Σελίδα manual του pidfd_open(2)](https://man7.org/linux/man-pages/man2/pidfd_open.2.html)
{{#include ../../../banners/hacktricks-training.md}}
