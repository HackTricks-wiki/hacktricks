# macOS xpc_connection_get_audit_token Attack

{{#include ../../../../../../banners/hacktricks-training.md}}

**Για περισσότερες πληροφορίες, ελέγξτε την αρχική δημοσίευση:** [**https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/**](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/). Αυτή είναι μια σύνοψη:

## Βασικές πληροφορίες για τα Mach Messages

Αν δεν γνωρίζετε τι είναι τα Mach Messages, ξεκινήστε ελέγχοντας αυτήν τη σελίδα:


{{#ref}}
../../
{{#endref}}

Προς το παρόν, θυμηθείτε ότι ([ορισμός από εδώ](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing)):\
Τα Mach messages αποστέλλονται μέσω ενός _mach port_, που είναι ένα **κανάλι επικοινωνίας single receiver, multiple sender** ενσωματωμένο στον mach kernel. **Πολλαπλά processes μπορούν να στέλνουν messages** σε ένα mach port, αλλά ανά πάσα στιγμή **μόνο ένα process μπορεί να διαβάζει από αυτό**. Όπως τα file descriptors και τα sockets, τα mach ports εκχωρούνται και διαχειρίζονται από τον kernel και τα processes βλέπουν μόνο έναν ακέραιο αριθμό, τον οποίο μπορούν να χρησιμοποιήσουν για να υποδείξουν στον kernel ποιο από τα mach ports τους θέλουν να χρησιμοποιήσουν.

## XPC Connection

Αν δεν γνωρίζετε πώς δημιουργείται μια XPC connection, ελέγξτε:


{{#ref}}
../
{{#endref}}

## Σύνοψη του Vuln

Αυτό που είναι σημαντικό να γνωρίζετε είναι ότι η **αφαίρεση του XPC είναι one-to-one connection**, αλλά βασίζεται σε τεχνολογία η οποία **μπορεί να έχει πολλαπλούς senders, επομένως:**

- Τα Mach ports είναι single receiver, **multiple sender**.
- Το audit token μιας XPC connection είναι το audit token **που αντιγράφηκε από το πιο πρόσφατα ληφθέν message**.
- Η λήψη του **audit token** μιας XPC connection είναι κρίσιμη για πολλούς **security checks**.<sup>[[1]](#references)</sup>

Παρότι η προηγούμενη κατάσταση φαίνεται υποσχόμενη, υπάρχουν ορισμένα σενάρια όπου δεν θα προκαλέσει προβλήματα ([από εδώ](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing)):

- Τα audit tokens χρησιμοποιούνται συχνά για authorization check, ώστε να αποφασιστεί αν θα γίνει αποδεκτή μια connection. Επειδή αυτό γίνεται με τη χρήση ενός message προς το service port, **δεν έχει δημιουργηθεί ακόμη connection**. Περισσότερα messages σε αυτό το port απλώς θα αντιμετωπιστούν ως πρόσθετα connection requests. Επομένως, **κανένα check πριν από την αποδοχή μιας connection δεν είναι ευάλωτο** (αυτό σημαίνει επίσης ότι μέσα στο `-listener:shouldAcceptNewConnection:` το audit token είναι ασφαλές). Επομένως, **αναζητούμε XPC connections που επαληθεύουν συγκεκριμένες ενέργειες**.
- Τα XPC event handlers διαχειρίζονται συγχρονισμένα. Αυτό σημαίνει ότι το event handler για ένα message πρέπει να ολοκληρωθεί πριν κληθεί για το επόμενο, ακόμη και σε concurrent dispatch queues. Επομένως, μέσα σε ένα **XPC event handler το audit token δεν μπορεί να αντικατασταθεί** από άλλα κανονικά (non-reply!) messages.<sup>[[1]](#references)</sup>

Υπάρχουν δύο διαφορετικές μέθοδοι με τις οποίες αυτό μπορεί να γίνει exploitable:

1. Variant1:
- Το **exploit** συνδέεται με το service **A** και το service **B**.
- Το service **B** μπορεί να καλέσει μια **privileged functionality** στο service A, την οποία ο χρήστης δεν μπορεί να καλέσει.
- Το service **A** καλεί το **`xpc_connection_get_audit_token`** ενώ _**δεν**_ βρίσκεται μέσα στο **event handler** για μια connection σε **`dispatch_async`**.
- Έτσι, ένα **διαφορετικό** message θα μπορούσε να **αντικαταστήσει το Audit Token**, επειδή γίνεται dispatch ασύγχρονα εκτός του event handler.
- Το exploit περνά στο **service B το SEND right προς το service A**.
- Επομένως, το svc **B** θα **στέλνει** στην πραγματικότητα τα **messages** προς το **service A**.
- Το **exploit** προσπαθεί να **καλέσει την privileged action**. Σε μια RC, το svc **A** **ελέγχει** το authorization αυτής της **action** ενώ το **svc B έχει αντικαταστήσει το Audit token** (παρέχοντας στο exploit πρόσβαση για την κλήση της privileged action).

2. Variant 2:
- Το service **B** μπορεί να καλέσει μια **privileged functionality** στο service A, την οποία ο χρήστης δεν μπορεί να καλέσει.
- Το exploit συνδέεται με το **service A**, το οποίο **στέλνει** στο exploit ένα **message που αναμένει response** σε ένα συγκεκριμένο **replay** **port**.
- Το exploit στέλνει στο **service** B ένα message, περνώντας **αυτό το reply port**.
- Όταν το service **B απαντήσει**, **στέλνει το message στο service A**, ενώ το **exploit** στέλνει ένα διαφορετικό **message στο service A**, προσπαθώντας να **φτάσει σε μια privileged functionality** και αναμένοντας ότι το reply από το service B θα αντικαταστήσει το Audit token την κατάλληλη στιγμή (Race Condition).

## Variant 1: calling xpc_connection_get_audit_token outside of an event handler <a href="#variant-1-calling-xpc_connection_get_audit_token-outside-of-an-event-handler" id="variant-1-calling-xpc_connection_get_audit_token-outside-of-an-event-handler"></a>

Σενάριο:

- Δύο mach services, τα **`A`** και **`B`**, στα οποία μπορούμε να συνδεθούμε και στα δύο (με βάση το sandbox profile και τα authorization checks πριν από την αποδοχή της connection).
- Το _**A**_ πρέπει να διαθέτει ένα **authorization check** για μια συγκεκριμένη action που το **`B`** μπορεί να περάσει (αλλά η εφαρμογή μας όχι).
- Για παράδειγμα, αν το B διαθέτει ορισμένα **entitlements** ή εκτελείται ως **root**, μπορεί να του επιτρέπεται να ζητήσει από το A την εκτέλεση μιας privileged action.
- Για αυτό το authorization check, το **A** λαμβάνει το audit token ασύγχρονα, για παράδειγμα καλώντας το `xpc_connection_get_audit_token` από το `dispatch_async`.

> [!CAUTION]
> Σε αυτήν την περίπτωση, ένας attacker θα μπορούσε να προκαλέσει ένα **Race Condition**, δημιουργώντας ένα **exploit** που ζητά από το A να εκτελέσει μια action πολλές φορές, ενώ κάνει το **B να στέλνει messages στο `A`**. Όταν το RC είναι **successful**, το **audit token** του **B** θα αντιγραφεί στη μνήμη **ενώ το request του exploit μας βρίσκεται υπό διαχείριση** από το A, παρέχοντάς του **πρόσβαση στην privileged action που θα μπορούσε να ζητήσει μόνο το B**.

Αυτό συνέβη με το **`A`** ως `smd` και το **`B`** ως `diagnosticd`. Η function [`SMJobBless`](https://developer.apple.com/documentation/servicemanagement/1431078-smjobbless?language=objc) από το smb μπορεί να χρησιμοποιηθεί για την εγκατάσταση ενός νέου privileged helper tool (ως **root**). Αν ένα **process που εκτελείται ως root επικοινωνήσει με το** **smd**, δεν θα πραγματοποιηθούν άλλοι έλεγχοι.

Επομένως, το service **B** είναι το **`diagnosticd`**, επειδή εκτελείται ως **root** και μπορεί να χρησιμοποιηθεί για την **παρακολούθηση** ενός process. Έτσι, μόλις ξεκινήσει η παρακολούθηση, θα **στέλνει πολλά messages ανά δευτερόλεπτο**.

Για την εκτέλεση του attack:

1. Ξεκινήστε μια **connection** προς το service με όνομα `smd`, χρησιμοποιώντας το standard XPC protocol.
2. Δημιουργήστε μια secondary **connection** προς το `diagnosticd`. Σε αντίθεση με την κανονική διαδικασία, αντί να δημιουργήσετε και να στείλετε δύο νέα mach ports, το client port send right αντικαθίσταται με ένα duplicate του **send right** που σχετίζεται με τη connection προς το `smd`.
3. Ως αποτέλεσμα, τα XPC messages μπορούν να γίνουν dispatch προς το `diagnosticd`, αλλά οι responses από το `diagnosticd` αναδρομολογούνται προς το `smd`. Για το `smd`, φαίνεται σαν τα messages τόσο από τον χρήστη όσο και από το `diagnosticd` να προέρχονται από την ίδια connection.

![Image depicting the exploit process](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/exploit.png)

4. Το επόμενο βήμα είναι να δοθεί εντολή στο `diagnosticd` να ξεκινήσει την παρακολούθηση ενός επιλεγμένου process (ενδεχομένως του ίδιου του χρήστη). Παράλληλα, αποστέλλεται στο `smd` ένα flood από κανονικά 1004 messages. Ο στόχος είναι η εγκατάσταση ενός tool με elevated privileges.
5. Αυτή η action προκαλεί ένα race condition μέσα στη function `handle_bless`. Ο χρονισμός είναι κρίσιμος: η κλήση της function `xpc_connection_get_pid` πρέπει να επιστρέψει το PID του process του χρήστη (καθώς το privileged tool βρίσκεται στο app bundle του χρήστη). Ωστόσο, η function `xpc_connection_get_audit_token`, συγκεκριμένα μέσα στη subroutine `connection_is_authorized`, πρέπει να αναφέρεται στο audit token που ανήκει στο `diagnosticd`.<sup>[[1]](#references)</sup>

## Variant 2: reply forwarding

Σε ένα περιβάλλον XPC (Cross-Process Communication), παρότι τα event handlers δεν εκτελούνται ταυτόχρονα, η διαχείριση των reply messages έχει μια μοναδική συμπεριφορά. Συγκεκριμένα, υπάρχουν δύο διαφορετικές μέθοδοι για την αποστολή messages που αναμένουν reply:

1. **`xpc_connection_send_message_with_reply`**: Εδώ, το XPC message λαμβάνεται και υποβάλλεται σε επεξεργασία σε μια καθορισμένη queue.
2. **`xpc_connection_send_message_with_reply_sync`**: Αντίθετα, σε αυτήν τη μέθοδο, το XPC message λαμβάνεται και υποβάλλεται σε επεξεργασία στην τρέχουσα dispatch queue.

Αυτή η διάκριση είναι κρίσιμη, επειδή επιτρέπει την πιθανότητα τα **reply packets να γίνονται parse ταυτόχρονα με την εκτέλεση ενός XPC event handler**. Σημειώστε ότι, παρόλο που το `_xpc_connection_set_creds` εφαρμόζει locking για προστασία από τη μερική αντικατάσταση του audit token, αυτή η προστασία δεν επεκτείνεται σε ολόκληρο το connection object. Κατά συνέπεια, δημιουργείται μια ευπάθεια όπου το audit token μπορεί να αντικατασταθεί στο χρονικό διάστημα μεταξύ του parsing ενός packet και της εκτέλεσης του event handler του.

Για την εκμετάλλευση αυτής της ευπάθειας απαιτείται η ακόλουθη ρύθμιση:

- Δύο mach services, τα οποία αναφέρονται ως **`A`** και **`B`**, και στα οποία μπορεί να δημιουργηθεί connection.
- Το service **`A`** πρέπει να περιλαμβάνει ένα authorization check για μια συγκεκριμένη action που μπορεί να εκτελέσει μόνο το **`B`** (η εφαρμογή του χρήστη δεν μπορεί).
- Το service **`A`** πρέπει να στείλει ένα message που αναμένει reply.
- Ο χρήστης μπορεί να στείλει ένα message στο **`B`**, στο οποίο αυτό θα απαντήσει.

Η διαδικασία exploitation περιλαμβάνει τα εξής βήματα:

1. Περιμένετε το service **`A`** να στείλει ένα message που αναμένει reply.
2. Αντί να απαντήσετε απευθείας στο **`A`**, το reply port γίνεται hijack και χρησιμοποιείται για την αποστολή ενός message στο service **`B`**.
3. Στη συνέχεια, γίνεται dispatch ενός message που αφορά την forbidden action, με την προσδοκία ότι θα υποβληθεί σε επεξεργασία ταυτόχρονα με το reply από το **`B`**.<sup>[[1]](#references)</sup>

Παρακάτω παρουσιάζεται μια οπτική αναπαράσταση του περιγραφόμενου attack scenario:

!\[https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/variant2.png]\(../../../../../../images/image (1) (1) (1) (1) (1) (1) (1).png)

<figure><img src="../../../../../../images/image (33).png" alt="https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/variant2.png" width="563"><figcaption></figcaption></figure>

## Προβλήματα Discovery

- **Δυσκολίες στον εντοπισμό instances**: Η αναζήτηση instances χρήσης του `xpc_connection_get_audit_token` ήταν δύσκολη, τόσο στατικά όσο και δυναμικά.
- **Μεθοδολογία**: Χρησιμοποιήθηκε το Frida για hook στη function `xpc_connection_get_audit_token`, με φιλτράρισμα των calls που δεν προέρχονταν από event handlers. Ωστόσο, αυτή η μέθοδος περιοριζόταν στο process όπου είχε εγκατασταθεί το hook και απαιτούσε ενεργή χρήση.
- **Analysis Tooling**: Tools όπως τα IDA/Ghidra χρησιμοποιήθηκαν για την εξέταση reachable mach services, αλλά η διαδικασία ήταν χρονοβόρα και περίπλοκη λόγω calls που περιλάμβαναν το dyld shared cache.
- **Περιορισμοί Scripting**: Οι προσπάθειες δημιουργίας script για την ανάλυση calls προς το `xpc_connection_get_audit_token` από `dispatch_async` blocks παρεμποδίστηκαν από την πολυπλοκότητα του parsing των blocks και των αλληλεπιδράσεων με το dyld shared cache.<sup>[[1]](#references)</sup>

## Η διόρθωση <a href="#the-fix" id="the-fix"></a>

- **Reported Issues**: Υποβλήθηκε report στην Apple, στο οποίο περιγράφονταν τα γενικά και ειδικά issues που εντοπίστηκαν στο `smd`.
- **Απόκριση της Apple**: Η Apple διόρθωσε το issue στο `smd`, αντικαθιστώντας το `xpc_connection_get_audit_token` με το `xpc_dictionary_get_audit_token`.<sup>[[1]](#references)[[2]](#references)</sup>
- **Φύση της διόρθωσης**: Η function `xpc_dictionary_get_audit_token` θεωρείται ασφαλής, επειδή ανακτά το audit token απευθείας από το mach message που σχετίζεται με το XPC message που λήφθηκε. Ωστόσο, δεν αποτελεί μέρος του public API, όπως και το `xpc_connection_get_audit_token`.
- **Απουσία ευρύτερης διόρθωσης**: Παραμένει ασαφές γιατί η Apple δεν υλοποίησε μια πιο ολοκληρωμένη διόρθωση, όπως την απόρριψη messages που δεν αντιστοιχούν στο αποθηκευμένο audit token της connection. Η πιθανότητα νόμιμων αλλαγών audit token σε ορισμένα σενάρια (π.χ. χρήση `setuid`) μπορεί να αποτελεί παράγοντα.
- **Τρέχουσα κατάσταση**: Το issue εξακολουθεί να υπάρχει στα iOS 17 και macOS 14, δημιουργώντας δυσκολίες σε όσους προσπαθούν να το εντοπίσουν και να το κατανοήσουν.<sup>[[1]](#references)</sup>

## Εντοπισμός ευάλωτων code paths στην πράξη (2024–2025)

Κατά τον έλεγχο XPC services για αυτήν την κατηγορία bug, επικεντρωθείτε σε authorization που πραγματοποιείται εκτός του event handler του message ή ταυτόχρονα με reply processing.

Hints για static triage:

- Αναζητήστε calls προς το `xpc_connection_get_audit_token` που είναι reachable από blocks σε ουρές μέσω `dispatch_async`/`dispatch_after` ή άλλων worker queues που εκτελούνται εκτός του message handler.
- Αναζητήστε authorization helpers που συνδυάζουν per-connection και per-message state (π.χ. λήψη PID από το `xpc_connection_get_pid`, αλλά audit token από το `xpc_connection_get_audit_token`).
- Σε κώδικα NSXPC, επαληθεύστε ότι τα checks γίνονται στο `-listener:shouldAcceptNewConnection:` ή, για per-message checks, ότι η υλοποίηση χρησιμοποιεί per-message audit token (π.χ. το dictionary του message μέσω `xpc_dictionary_get_audit_token` σε lower-level code).

Hints για dynamic triage:

- Κάντε hook στο `xpc_connection_get_audit_token` και επισημάνετε invocations των οποίων το user stack δεν περιλαμβάνει το event-delivery path (π.χ. `_xpc_connection_mach_event`). Παράδειγμα Frida hook:
```javascript
Interceptor.attach(Module.getExportByName(null, 'xpc_connection_get_audit_token'), {
onEnter(args) {
const bt = Thread.backtrace(this.context, Backtracer.ACCURATE)
.map(DebugSymbol.fromAddress).join('\n');
if (!bt.includes('_xpc_connection_mach_event')) {
console.log('[!] xpc_connection_get_audit_token outside handler\n' + bt);
}
}
});
```
Σημειώσεις:
- Στο macOS, η instrumenting προστατευμένων/Apple binaries ενδέχεται να απαιτεί απενεργοποιημένο SIP ή development environment· προτιμήστε τη δοκιμή των δικών σας builds ή userland services.
- Για reply-forwarding races (Variant 2), παρακολουθήστε το concurrent parsing των reply packets κάνοντας fuzzing στα timings του `xpc_connection_send_message_with_reply` έναντι των normal requests και ελέγχοντας αν μπορεί να επηρεαστεί το effective audit token που χρησιμοποιείται κατά την authorization.

## Exploitation primitives που πιθανότατα θα χρειαστείτε

- Multi-sender setup (Variant 1): δημιουργήστε connections προς τα A και B· κάντε duplicate το send right του client port του A και χρησιμοποιήστε το ως client port του B, ώστε τα replies του B να παραδίδονται στο A.
```c
// Duplicate a SEND right you already hold
mach_port_t dup;
mach_port_insert_right(mach_task_self(), a_client, a_client, MACH_MSG_TYPE_MAKE_SEND);
dup = a_client; // use `dup` when crafting B’s connect packet instead of a fresh client port
```
- Reply hijack (Variant 2): υποκλοπή του send-once right από το pending request του A (reply port) και, στη συνέχεια, αποστολή crafted message στο B χρησιμοποιώντας αυτό το reply port, ώστε η απάντηση του B να καταλήξει στον A ενώ το privileged request σας αναλύεται.

Αυτές οι τεχνικές απαιτούν low-level mach message crafting για τα XPC bootstrap και message formats. Ανατρέξτε στις σελίδες mach/XPC primer αυτής της ενότητας για τις ακριβείς packet layouts και flags.

## Χρήσιμα εργαλεία

- XPC sniffing/dynamic inspection: το gxpc (open-source XPC sniffer) μπορεί να βοηθήσει στην απαρίθμηση connections και στην παρακολούθηση traffic, ώστε να επαληθεύσετε multi-sender setups και timing. Παράδειγμα: `gxpc -p <PID> --whitelist <service-name>`.
- Classic dyld interposing για το libxpc: κάντε interpose στα `xpc_connection_send_message*` και `xpc_connection_get_audit_token` για να καταγράφετε call sites και stacks κατά τη διάρκεια black-box testing.



## References

- [1] [Sector 7 – Don’t Talk All at Once! Elevating Privileges on macOS by Audit Token Spoofing](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)
- [2] [Apple – About the security content of macOS Ventura 13.4 (CVE‑2023‑32405)](https://support.apple.com/en-us/106333)


{{#include ../../../../../../banners/hacktricks-training.md}}
