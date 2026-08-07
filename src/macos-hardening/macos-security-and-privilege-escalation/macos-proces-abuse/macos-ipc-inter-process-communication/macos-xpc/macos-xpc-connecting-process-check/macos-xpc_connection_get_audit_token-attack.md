# macOS xpc_connection_get_audit_token Attack

{{#include ../../../../../../banners/hacktricks-training.md}}

**Για περισσότερες πληροφορίες, δείτε το original post:** [**https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/**](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/). Αυτή είναι μια περίληψη:<sup>[[1]](#references)</sup>

## Βασικές πληροφορίες για τα Mach Messages

Αν δεν γνωρίζετε τι είναι τα Mach Messages, ξεκινήστε ελέγχοντας αυτήν τη σελίδα:


{{#ref}}
../../
{{#endref}}

Προς το παρόν, θυμηθείτε ότι ([ορισμός από εδώ](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing)):<sup>[[1]](#references)</sup>\
Τα Mach messages αποστέλλονται μέσω ενός _mach port_, το οποίο είναι ένα κανάλι **επικοινωνίας με έναν receiver και πολλαπλούς senders**, ενσωματωμένο στον mach kernel. **Πολλαπλές διεργασίες μπορούν να στέλνουν messages** σε ένα mach port, αλλά ανά πάσα στιγμή **μόνο μία διεργασία μπορεί να διαβάζει από αυτό**. Όπως τα file descriptors και τα sockets, τα mach ports εκχωρούνται και διαχειρίζονται από τον kernel και οι διεργασίες βλέπουν μόνο έναν ακέραιο αριθμό, τον οποίο μπορούν να χρησιμοποιήσουν για να υποδείξουν στον kernel ποιο από τα mach ports τους θέλουν να χρησιμοποιήσουν.

## XPC Connection

Αν δεν γνωρίζετε πώς εγκαθιδρύεται ένα XPC connection, ελέγξτε:


{{#ref}}
../
{{#endref}}

## Περίληψη του Vuln

Αυτό που είναι σημαντικό να γνωρίζετε είναι ότι η **abstraction του XPC είναι μια one-to-one connection**, αλλά βασίζεται σε μια τεχνολογία η οποία **μπορεί να έχει πολλαπλούς senders, επομένως:**

- Τα Mach ports έχουν έναν receiver και **πολλαπλούς senders**.
- Το audit token ενός XPC connection είναι το audit token **που αντιγράφηκε από το πιο πρόσφατα ληφθέν message**.
- Η απόκτηση του **audit token** ενός XPC connection είναι κρίσιμη για πολλούς **security checks**.<sup>[[1]](#references)</sup>

Παρόλο που η προηγούμενη κατάσταση φαίνεται υποσχόμενη, υπάρχουν ορισμένα σενάρια στα οποία αυτό δεν θα προκαλέσει προβλήματα ([από εδώ](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing)):<sup>[[1]](#references)</sup>

- Τα audit tokens χρησιμοποιούνται συχνά για authorization check, ώστε να αποφασιστεί αν θα γίνει αποδεκτό ένα connection. Καθώς αυτό γίνεται με τη χρήση ενός message προς το service port, **δεν έχει ακόμη εγκαθιδρυθεί connection**. Περισσότερα messages σε αυτό το port απλώς θα αντιμετωπιστούν ως πρόσθετα connection requests. Επομένως, **οι checks πριν από την αποδοχή ενός connection δεν είναι vulnerable** (αυτό σημαίνει επίσης ότι μέσα στο `-listener:shouldAcceptNewConnection:` το audit token είναι ασφαλές). Επομένως, **αναζητούμε XPC connections που επαληθεύουν συγκεκριμένες ενέργειες**.
- Τα XPC event handlers υποβάλλονται σε synchronous επεξεργασία. Αυτό σημαίνει ότι το event handler για ένα message πρέπει να ολοκληρωθεί πριν κληθεί για το επόμενο, ακόμη και σε concurrent dispatch queues. Επομένως, μέσα σε ένα **XPC event handler το audit token δεν μπορεί να αντικατασταθεί** από άλλα κανονικά (non-reply!) messages.<sup>[[1]](#references)</sup>

Υπάρχουν δύο διαφορετικές μέθοδοι με τις οποίες αυτό μπορεί να γίνει exploitable:

1. Variant1:
- Το **Exploit** κάνει **connect** στα services **A** και **B**.
- Το service **B** μπορεί να καλέσει μια **privileged functionality** στο service A, την οποία ο χρήστης δεν μπορεί να καλέσει.
- Το service **A** καλεί το **`xpc_connection_get_audit_token`** ενώ _**δεν**_ βρίσκεται μέσα στο **event handler** για ένα connection σε ένα **`dispatch_async`**.
- Επομένως, ένα **διαφορετικό** message θα μπορούσε να **αντικαταστήσει το Audit Token**, επειδή γίνεται dispatch ασύγχρονα εκτός του event handler.
- Το exploit περνά στο **service B** το **SEND right προς το service A**.
- Επομένως, το svc **B** θα **στέλνει** στην πραγματικότητα τα **messages** προς το **service A**.
- Το **exploit** προσπαθεί να **καλέσει την privileged action**. Σε μια RC, το svc **A** **ελέγχει** το authorization αυτής της **action** ενώ το **svc B έχει αντικαταστήσει το Audit token** (παρέχοντας στο exploit πρόσβαση για να καλέσει την privileged action).
2. Variant 2:
- Το service **B** μπορεί να καλέσει μια **privileged functionality** στο service A, την οποία ο χρήστης δεν μπορεί να καλέσει.
- Το exploit κάνει connect με το **service A**, το οποίο **στέλνει** στο exploit ένα **message που αναμένει response** σε ένα συγκεκριμένο **replay** **port**.
- Το exploit στέλνει στο **service B** ένα message, μεταβιβάζοντας **εκείνο το reply port**.
- Όταν το service **B** απαντά, **στέλνει το message στο service A**, ενώ το **exploit** στέλνει ένα διαφορετικό **message στο service A**, προσπαθώντας να **προσπελάσει μια privileged functionality** και αναμένοντας ότι το reply από το service B θα αντικαταστήσει το Audit token την κατάλληλη στιγμή (Race Condition).

## Variant 1: κλήση του xpc_connection_get_audit_token εκτός event handler <a href="#variant-1-calling-xpc_connection_get_audit_token-outside-of-an-event-handler" id="variant-1-calling-xpc_connection_get_audit_token-outside-of-an-event-handler"></a>

Σενάριο:

- Υπάρχουν δύο mach services, τα **`A`** και **`B`**, στα οποία μπορούμε να συνδεθούμε και στα δύο (με βάση το sandbox profile και τα authorization checks πριν από την αποδοχή του connection).
- Το _**A**_ πρέπει να έχει ένα **authorization check** για μια συγκεκριμένη action, το οποίο το **`B`** μπορεί να περάσει (αλλά η εφαρμογή μας όχι).
- Για παράδειγμα, αν το B έχει κάποια **entitlements** ή εκτελείται ως **root**, μπορεί να του επιτρέπεται να ζητήσει από το A να εκτελέσει μια privileged action.
- Για αυτό το authorization check, το **`A`** λαμβάνει το audit token ασύγχρονα, για παράδειγμα καλώντας το `xpc_connection_get_audit_token` από ένα `dispatch_async`.

> [!CAUTION]
> Σε αυτήν την περίπτωση, ένας attacker θα μπορούσε να προκαλέσει ένα **Race Condition**, δημιουργώντας ένα **exploit** που ζητά από το A να εκτελέσει μια action πολλές φορές, ενώ κάνει το **B να στέλνει messages προς το `A`**. Όταν το RC είναι **successful**, το **audit token** του **B** θα αντιγραφεί στη μνήμη **ενώ το request του exploit** υποβάλλεται σε επεξεργασία από το A, παρέχοντάς του **πρόσβαση στην privileged action που μόνο το B θα μπορούσε να ζητήσει**.

Αυτό συνέβη με το **`A`** ως `smd` και το **`B`** ως `diagnosticd`. Η function [`SMJobBless`](https://developer.apple.com/documentation/servicemanagement/1431078-smjobbless?language=objc) από το smb μπορεί να χρησιμοποιηθεί για την εγκατάσταση ενός νέου privileged helper toot (ως **root**). Αν μια **process running as root contact** το **smd**, δεν θα πραγματοποιηθούν άλλοι checks.

Επομένως, το service **B** είναι το **`diagnosticd`**, επειδή εκτελείται ως **root** και μπορεί να χρησιμοποιηθεί για την **παρακολούθηση** μιας process, οπότε, μόλις ξεκινήσει η παρακολούθηση, θα **στέλνει multiple messages per second**.

Για την εκτέλεση του attack:

1. Ξεκινήστε ένα **connection** προς το service με όνομα `smd`, χρησιμοποιώντας το standard XPC protocol.
2. Δημιουργήστε ένα secondary **connection** προς το `diagnosticd`. Σε αντίθεση με τη normal διαδικασία, αντί να δημιουργηθούν και να σταλούν δύο νέα mach ports, το client port send right αντικαθίσταται με ένα duplicate του **send right** που σχετίζεται με το connection προς το `smd`.
3. Ως αποτέλεσμα, τα XPC messages μπορούν να γίνουν dispatch προς το `diagnosticd`, αλλά οι responses από το `diagnosticd` αναδρομολογούνται στο `smd`. Για το `smd`, φαίνεται σαν τα messages τόσο από τον χρήστη όσο και από το `diagnosticd` να προέρχονται από το ίδιο connection.

![Image depicting the exploit process](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/exploit.png)

4. Το επόμενο βήμα περιλαμβάνει την εντολή στο `diagnosticd` να ξεκινήσει την παρακολούθηση μιας επιλεγμένης process (ενδεχομένως της ίδιας της process του χρήστη). Ταυτόχρονα, αποστέλλεται στο `smd` ένα flood από τυπικά 1004 messages. Στόχος είναι η εγκατάσταση ενός tool με elevated privileges.
5. Αυτή η action προκαλεί ένα race condition μέσα στη function `handle_bless`. Ο χρονισμός είναι κρίσιμος: η κλήση της function `xpc_connection_get_pid` πρέπει να επιστρέψει το PID της process του χρήστη (καθώς το privileged tool βρίσκεται στο bundle της εφαρμογής του χρήστη). Ωστόσο, η function `xpc_connection_get_audit_token`, συγκεκριμένα μέσα στο subroutine `connection_is_authorized`, πρέπει να αναφέρεται στο audit token που ανήκει στο `diagnosticd`.<sup>[[1]](#references)</sup>

## Variant 2: reply forwarding

Σε ένα περιβάλλον XPC (Cross-Process Communication), παρόλο που τα event handlers δεν εκτελούνται ταυτόχρονα, η διαχείριση των reply messages έχει μοναδική συμπεριφορά. Συγκεκριμένα, υπάρχουν δύο διαφορετικές μέθοδοι για την αποστολή messages που αναμένουν reply:

1. **`xpc_connection_send_message_with_reply`**: Εδώ, το XPC message λαμβάνεται και υποβάλλεται σε επεξεργασία σε μια καθορισμένη queue.
2. **`xpc_connection_send_message_with_reply_sync`**: Αντίθετα, σε αυτήν τη μέθοδο, το XPC message λαμβάνεται και υποβάλλεται σε επεξεργασία στην τρέχουσα dispatch queue.

Αυτή η διάκριση είναι κρίσιμη, επειδή επιτρέπει την πιθανότητα **reply packets να γίνονται parse concurrently με την εκτέλεση ενός XPC event handler**. Συγκεκριμένα, ενώ το `_xpc_connection_set_creds` εφαρμόζει locking για προστασία από τη μερική αντικατάσταση του audit token, αυτή η προστασία δεν επεκτείνεται σε ολόκληρο το connection object. Κατά συνέπεια, δημιουργείται ένα vulnerability όπου το audit token μπορεί να αντικατασταθεί στο διάστημα μεταξύ του parsing ενός packet και της εκτέλεσης του event handler του.

Για την εκμετάλλευση αυτού του vulnerability, απαιτείται η ακόλουθη εγκατάσταση:

- Δύο mach services, τα οποία αναφέρονται ως **`A`** και **`B`**, και στα δύο από τα οποία μπορεί να εγκατασταθεί connection.
- Το service **`A`** πρέπει να περιλαμβάνει ένα authorization check για μια συγκεκριμένη action, την οποία μπορεί να εκτελέσει μόνο το **`B`** (η εφαρμογή του χρήστη δεν μπορεί).
- Το service **`A`** πρέπει να στείλει ένα message που αναμένει reply.
- Ο χρήστης μπορεί να στείλει ένα message στο **`B`**, στο οποίο αυτό θα απαντήσει.

Η διαδικασία exploitation περιλαμβάνει τα εξής βήματα:

1. Περιμένετε μέχρι το service **`A`** να στείλει ένα message που αναμένει reply.
2. Αντί να απαντήσει απευθείας στο **`A`**, το reply port γίνεται hijack και χρησιμοποιείται για την αποστολή ενός message στο service **`B`**.
3. Στη συνέχεια, γίνεται dispatch ενός message που περιλαμβάνει την forbidden action, με την προσδοκία ότι θα υποβληθεί σε επεξεργασία concurrently με το reply από το **`B`**.<sup>[[1]](#references)</sup>

Παρακάτω παρουσιάζεται μια οπτική αναπαράσταση του περιγραφόμενου attack scenario:

!\[https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/variant2.png]\(../../../../../../images/image (1) (1) (1) (1) (1) (1) (1).png)

<figure><img src="../../../../../../images/image (33).png" alt="https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/variant2.png" width="563"><figcaption></figcaption></figure>

## Προβλήματα Discovery

- **Δυσκολίες στον εντοπισμό Instances**: Η αναζήτηση instances χρήσης του `xpc_connection_get_audit_token` ήταν δύσκολη, τόσο στατικά όσο και δυναμικά.
- **Methodology**: Χρησιμοποιήθηκε το Frida για hook στη function `xpc_connection_get_audit_token`, με φιλτράρισμα των calls που δεν προέρχονταν από event handlers. Ωστόσο, αυτή η μέθοδος περιοριζόταν στη hooked process και απαιτούσε ενεργή χρήση.
- **Analysis Tooling**: Χρησιμοποιήθηκαν εργαλεία όπως τα IDA/Ghidra για την εξέταση reachable mach services, αλλά η διαδικασία ήταν χρονοβόρα και περιπλεκόταν από calls που σχετίζονταν με το dyld shared cache.
- **Scripting Limitations**: Οι προσπάθειες δημιουργίας script για την ανάλυση calls προς το `xpc_connection_get_audit_token` από `dispatch_async` blocks παρεμποδίστηκαν από την πολυπλοκότητα του parsing των blocks και των interactions με το dyld shared cache.<sup>[[1]](#references)</sup>

## Η διόρθωση <a href="#the-fix" id="the-fix"></a>

- **Reported Issues**: Υποβλήθηκε report στην Apple, στο οποίο περιγράφονταν τα γενικά και τα συγκεκριμένα issues που εντοπίστηκαν στο `smd`.
- **Apple's Response**: Η Apple αντιμετώπισε το issue στο `smd`, αντικαθιστώντας το `xpc_connection_get_audit_token` με το `xpc_dictionary_get_audit_token`.<sup>[[1]](#references)[[2]](#references)</sup>
- **Nature of the Fix**: Η function `xpc_dictionary_get_audit_token` θεωρείται secure, καθώς ανακτά το audit token απευθείας από το mach message που συνδέεται με το ληφθέν XPC message. Ωστόσο, δεν αποτελεί μέρος του public API, όπως και το `xpc_connection_get_audit_token`.
- **Absence of a Broader Fix**: Παραμένει ασαφές γιατί η Apple δεν υλοποίησε μια πιο comprehensive fix, όπως την απόρριψη messages που δεν αντιστοιχούν στο αποθηκευμένο audit token του connection. Η πιθανότητα νόμιμων αλλαγών audit token σε ορισμένα σενάρια (π.χ. χρήση `setuid`) μπορεί να αποτελεί παράγοντα.
- **Current Status**: Το issue εξακολουθεί να υπάρχει στα iOS 17 και macOS 14, αποτελώντας πρόκληση για όσους προσπαθούν να το εντοπίσουν και να το κατανοήσουν.<sup>[[1]](#references)</sup>

## Εντοπισμός vulnerable code paths στην πράξη (2024–2025)

Κατά τον έλεγχο XPC services για αυτήν την κατηγορία bug, επικεντρωθείτε σε authorization που πραγματοποιείται εκτός του event handler του message ή concurrently με reply processing.

Υποδείξεις για static triage:
- Αναζητήστε calls προς το `xpc_connection_get_audit_token` που είναι reachable από blocks τα οποία μπαίνουν σε queue μέσω `dispatch_async`/`dispatch_after` ή άλλων worker queues που εκτελούνται εκτός του message handler.
- Αναζητήστε authorization helpers που συνδυάζουν per-connection και per-message state (π.χ. ανάκτηση του PID από το `xpc_connection_get_pid`, αλλά του audit token από το `xpc_connection_get_audit_token`).
- Σε κώδικα NSXPC, επαληθεύστε ότι οι checks πραγματοποιούνται στο `-listener:shouldAcceptNewConnection:` ή, για per-message checks, ότι η υλοποίηση χρησιμοποιεί per-message audit token (π.χ. το dictionary του message μέσω του `xpc_dictionary_get_audit_token` σε lower-level code).

Υποδείξεις για dynamic triage:
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
- Στο macOS, η instrumenting προστατευμένων/Apple binaries μπορεί να απαιτεί απενεργοποιημένο SIP ή development environment· προτιμήστε δοκιμές στα δικά σας builds ή σε userland services.
- Για reply-forwarding races (Variant 2), παρακολουθήστε την ταυτόχρονη ανάλυση των reply packets, κάνοντας fuzzing στους χρονισμούς των `xpc_connection_send_message_with_reply` σε σύγκριση με τα κανονικά requests και ελέγχοντας αν το effective audit token που χρησιμοποιείται κατά την authorization μπορεί να επηρεαστεί.

## Exploitation primitives που πιθανότατα θα χρειαστείτε

- Multi-sender setup (Variant 1): δημιουργήστε connections προς τα A και B· κάντε duplicate το send right του client port του A και χρησιμοποιήστε το ως client port του B, ώστε τα replies του B να παραδίδονται στο A.
```c
// Duplicate a SEND right you already hold
mach_port_t dup;
mach_port_insert_right(mach_task_self(), a_client, a_client, MACH_MSG_TYPE_MAKE_SEND);
dup = a_client; // use `dup` when crafting B’s connect packet instead of a fresh client port
```
- Reply hijack (Variant 2): capture το send-once right από το pending request του A (reply port) και, στη συνέχεια, στείλε ένα crafted message στο B χρησιμοποιώντας αυτό το reply port, ώστε η απάντηση του B να καταλήξει στο A ενώ το privileged request σου γίνεται parsed.

Αυτά απαιτούν low-level mach message crafting για τα XPC bootstrap και message formats. Δες τις σελίδες mach/XPC primer σε αυτή την ενότητα για τα ακριβή packet layouts και flags.

## Χρήσιμα εργαλεία

- XPC sniffing/dynamic inspection: το gxpc (open-source XPC sniffer) μπορεί να βοηθήσει στην απαρίθμηση connections και στην παρατήρηση traffic, ώστε να επικυρώσεις multi-sender setups και timing. Παράδειγμα: `gxpc -p <PID> --whitelist <service-name>`.
- Classic dyld interposing για το libxpc: κάνε interpose στα `xpc_connection_send_message*` και `xpc_connection_get_audit_token`, ώστε να καταγράφεις call sites και stacks κατά τη διάρκεια black-box testing.



## Αναφορές

- [1] [Sector 7 – Don’t Talk All at Once! Elevating Privileges on macOS by Audit Token Spoofing](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)
- [2] [Apple – About the security content of macOS Ventura 13.4 (CVE‑2023‑32405)](https://support.apple.com/en-us/106333)


{{#include ../../../../../../banners/hacktricks-training.md}}
