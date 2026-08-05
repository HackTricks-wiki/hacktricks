# macOS xpc_connection_get_audit_token Attack

{{#include ../../../../../../banners/hacktricks-training.md}}

**Για περισσότερες πληροφορίες, δείτε το original post:** [**https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/**](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/). Ακολουθεί μια περίληψη:

## Βασικές πληροφορίες για Mach Messages

Αν δεν γνωρίζετε τι είναι τα Mach Messages, ξεκινήστε ελέγχοντας αυτήν τη σελίδα:


{{#ref}}
../../
{{#endref}}

Προς το παρόν, θυμηθείτε ότι ([ορισμός από εδώ](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing)):\  
Τα Mach messages αποστέλλονται μέσω ενός _mach port_, το οποίο είναι ένα κανάλι επικοινωνίας **single receiver, multiple sender** ενσωματωμένο στον mach kernel. **Πολλαπλές διεργασίες μπορούν να στέλνουν messages** σε ένα mach port, αλλά ανά πάσα στιγμή **μόνο μία διεργασία μπορεί να διαβάζει από αυτό**. Όπως τα file descriptors και τα sockets, τα mach ports εκχωρούνται και διαχειρίζονται από τον kernel, ενώ οι διεργασίες βλέπουν μόνο έναν ακέραιο αριθμό, τον οποίο μπορούν να χρησιμοποιήσουν για να υποδείξουν στον kernel ποιο από τα mach ports τους θέλουν να χρησιμοποιήσουν.

## XPC Connection

Αν δεν γνωρίζετε πώς δημιουργείται μια XPC connection, ελέγξτε:


{{#ref}}
../
{{#endref}}

## Περίληψη ευπάθειας

Αυτό που είναι σημαντικό να γνωρίζετε είναι ότι η **αφαίρεση του XPC είναι one-to-one connection**, αλλά βασίζεται σε μια τεχνολογία που **μπορεί να έχει πολλαπλούς senders, επομένως:**

- Τα Mach ports είναι single receiver, **multiple sender**.
- Το audit token μιας XPC connection είναι το audit token που **αντιγράφεται από το πιο πρόσφατα ληφθέν message**.
- Η λήψη του **audit token** μιας XPC connection είναι κρίσιμη για πολλούς **security checks**.<sup>[1]</sup>

Παρόλο που η προηγούμενη κατάσταση φαίνεται πολλά υποσχόμενη, υπάρχουν ορισμένα σενάρια στα οποία δεν πρόκειται να προκαλέσει προβλήματα ([από εδώ](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing)):

- Τα audit tokens χρησιμοποιούνται συχνά για authorization check, ώστε να αποφασιστεί αν θα γίνει αποδεκτή μια connection. Επειδή αυτό γίνεται μέσω ενός message προς το service port, **δεν έχει δημιουργηθεί ακόμη connection**. Περισσότερα messages σε αυτό το port θα αντιμετωπιστούν απλώς ως επιπλέον αιτήματα σύνδεσης. Επομένως, **οι checks πριν από την αποδοχή μιας connection δεν είναι vulnerable** (αυτό σημαίνει επίσης ότι μέσα στο `-listener:shouldAcceptNewConnection:` το audit token είναι ασφαλές). Επομένως, **αναζητούμε XPC connections που επαληθεύουν συγκεκριμένες ενέργειες**.
- Οι XPC event handlers εκτελούνται synchronously. Αυτό σημαίνει ότι ο event handler ενός message πρέπει να ολοκληρωθεί πριν κληθεί για το επόμενο, ακόμη και σε concurrent dispatch queues. Επομένως, μέσα σε έναν **XPC event handler το audit token δεν μπορεί να overwritten** από άλλα κανονικά (non-reply!) messages.<sup>[1]</sup>

Υπάρχουν δύο διαφορετικές μέθοδοι με τις οποίες αυτό μπορεί να γίνει exploitable:

1. Variant1:
- Το **Exploit** **συνδέεται** στα services **A** και **B**.
- Το service **B** μπορεί να καλέσει μια **privileged functionality** στο service A, την οποία ο χρήστης δεν μπορεί να καλέσει.
- Το service **A** καλεί το **`xpc_connection_get_audit_token`** ενώ _**δεν**_ βρίσκεται μέσα στον **event handler** μιας connection σε ένα **`dispatch_async`**.
- Επομένως, ένα **διαφορετικό** message θα μπορούσε να **overwrite το Audit Token**, επειδή γίνεται dispatch asynchronously εκτός του event handler.
- Το exploit περνά στο **service B το SEND right προς το service A**.
- Έτσι, το svc **B** θα **στέλνει** στην πραγματικότητα τα **messages** προς το **service A**.
- Το **exploit** προσπαθεί να **καλέσει την privileged action**. Σε μια RC, το svc **A** **ελέγχει** το authorization αυτής της **action**, ενώ το **svc B έχει overwritten το Audit token** (δίνοντας στο exploit πρόσβαση στην κλήση της privileged action).
2. Variant 2:
- Το service **B** μπορεί να καλέσει μια **privileged functionality** στο service A, την οποία ο χρήστης δεν μπορεί να καλέσει.
- Το exploit συνδέεται με το **service A**, το οποίο **στέλνει** στο exploit ένα **message που αναμένει response** σε ένα συγκεκριμένο **replay** **port**.
- Το exploit στέλνει στο **service B** ένα message περνώντας **αυτό το reply port**.
- Όταν το service **B απαντά**, **στέλνει το message στο service A**, ενώ το **exploit** στέλνει ένα διαφορετικό **message στο service A**, προσπαθώντας να **φτάσει σε μια privileged functionality** και αναμένοντας ότι το reply από το service B θα κάνει overwrite το Audit token την κατάλληλη στιγμή (Race Condition).

## Variant 1: calling xpc_connection_get_audit_token outside of an event handler <a href="#variant-1-calling-xpc_connection_get_audit_token-outside-of-an-event-handler" id="variant-1-calling-xpc_connection_get_audit_token-outside-of-an-event-handler"></a>

Σενάριο:

- Δύο mach services, τα **`A`** και **`B`**, στα οποία μπορούμε να συνδεθούμε και στα δύο (με βάση το sandbox profile και τα authorization checks πριν από την αποδοχή της connection).
- Το _**A**_ πρέπει να έχει ένα **authorization check** για μια συγκεκριμένη action, την οποία το **`B`** μπορεί να περάσει (αλλά η εφαρμογή μας δεν μπορεί).
- Για παράδειγμα, αν το B έχει κάποια **entitlements** ή εκτελείται ως **root**, μπορεί να του επιτρέπεται να ζητήσει από το A να εκτελέσει μια privileged action.
- Για αυτό το authorization check, το **A** λαμβάνει το audit token asynchronously, για παράδειγμα καλώντας το `xpc_connection_get_audit_token` από το `dispatch_async`.

> [!CAUTION]
> Σε αυτήν την περίπτωση, ένας attacker θα μπορούσε να προκαλέσει ένα **Race Condition**, δημιουργώντας ένα **exploit** που ζητά από το A να εκτελέσει μια action πολλές φορές, ενώ κάνει το **B να στέλνει messages στο `A`**. Όταν το RC είναι **successful**, το **audit token** του **B** θα αντιγραφεί στη μνήμη **ενώ το request του exploit μας βρίσκεται υπό επεξεργασία** από το A, δίνοντάς του **πρόσβαση στην privileged action που μόνο το B θα μπορούσε να ζητήσει**.

Αυτό συνέβη με το **`A`** ως `smd` και το **`B`** ως `diagnosticd`. Η function [`SMJobBless`](https://developer.apple.com/documentation/servicemanagement/1431078-smjobbless?language=objc) από το smb μπορεί να χρησιμοποιηθεί για την εγκατάσταση ενός νέου privileged helper tool (ως **root**). Αν μια **process running as root επικοινωνήσει με το** **`smd`**, δεν θα πραγματοποιηθούν άλλοι checks.

Επομένως, το service **B** είναι το **`diagnosticd`**, επειδή εκτελείται ως **root** και μπορεί να χρησιμοποιηθεί για **monitor** μιας process. Έτσι, μόλις ξεκινήσει το monitoring, θα **στέλνει πολλαπλά messages ανά δευτερόλεπτο**.

Για την εκτέλεση της attack:

1. Ξεκινήστε μια **connection** προς το service με όνομα `smd` χρησιμοποιώντας το standard XPC protocol.
2. Δημιουργήστε μια secondary **connection** προς το `diagnosticd`. Σε αντίθεση με τη συνήθη διαδικασία, αντί να δημιουργηθούν και να σταλούν δύο νέα mach ports, το client port send right αντικαθίσταται από ένα duplicate του **send right** που σχετίζεται με τη connection προς το `smd`.
3. Ως αποτέλεσμα, τα XPC messages μπορούν να γίνουν dispatch προς το `diagnosticd`, αλλά τα responses από το `diagnosticd` αναδρομολογούνται προς το `smd`. Για το `smd`, φαίνεται σαν τα messages τόσο από τον χρήστη όσο και από το `diagnosticd` να προέρχονται από την ίδια connection.

![Image depicting the exploit process](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/exploit.png)

4. Το επόμενο βήμα περιλαμβάνει την εντολή προς το `diagnosticd` να ξεκινήσει monitoring μιας επιλεγμένης process (ενδεχομένως της ίδιας της process του χρήστη). Παράλληλα, αποστέλλεται στο `smd` ένα flood από συνηθισμένα 1004 messages. Ο στόχος είναι να εγκατασταθεί ένα tool με elevated privileges.
5. Αυτή η action προκαλεί ένα race condition μέσα στη function `handle_bless`. Ο χρονισμός είναι κρίσιμος: η κλήση της function `xpc_connection_get_pid` πρέπει να επιστρέψει το PID της process του χρήστη (καθώς το privileged tool βρίσκεται στο bundle της εφαρμογής του χρήστη). Ωστόσο, η function `xpc_connection_get_audit_token`, συγκεκριμένα μέσα στο subroutine `connection_is_authorized`, πρέπει να αναφέρεται στο audit token που ανήκει στο `diagnosticd`.<sup>[1]</sup>

## Variant 2: reply forwarding

Σε ένα περιβάλλον XPC (Cross-Process Communication), παρόλο που οι event handlers δεν εκτελούνται concurrently, η διαχείριση των reply messages έχει μια ιδιαίτερη συμπεριφορά. Συγκεκριμένα, υπάρχουν δύο διαφορετικές μέθοδοι για την αποστολή messages που αναμένουν reply:

1. **`xpc_connection_send_message_with_reply`**: Εδώ, το XPC message λαμβάνεται και υποβάλλεται σε επεξεργασία σε μια καθορισμένη queue.
2. **`xpc_connection_send_message_with_reply_sync`**: Αντίθετα, σε αυτήν τη μέθοδο, το XPC message λαμβάνεται και υποβάλλεται σε επεξεργασία στην τρέχουσα dispatch queue.

Αυτή η διάκριση είναι κρίσιμη, επειδή επιτρέπει την πιθανότητα **reply packets να γίνονται parsed concurrently με την εκτέλεση ενός XPC event handler**. Αξίζει να σημειωθεί ότι, ενώ το `_xpc_connection_set_creds` υλοποιεί locking για την προστασία από partial overwrite του audit token, αυτή η προστασία δεν επεκτείνεται σε ολόκληρο το connection object. Κατά συνέπεια, δημιουργείται μια vulnerability όπου το audit token μπορεί να αντικατασταθεί στο διάστημα μεταξύ του parsing ενός packet και της εκτέλεσης του event handler του.

Για την εκμετάλλευση αυτής της vulnerability απαιτείται η ακόλουθη setup:

- Δύο mach services, τα οποία αναφέρονται ως **`A`** και **`B`**, και στα δύο από τα οποία μπορεί να δημιουργηθεί connection.
- Το service **`A`** πρέπει να περιλαμβάνει ένα authorization check για μια συγκεκριμένη action που μπορεί να εκτελέσει μόνο το **`B`** (η εφαρμογή του χρήστη δεν μπορεί).
- Το service **`A`** πρέπει να στείλει ένα message που αναμένει reply.
- Ο χρήστης μπορεί να στείλει ένα message στο **`B`**, στο οποίο αυτό θα απαντήσει.

Η διαδικασία exploitation περιλαμβάνει τα εξής βήματα:

1. Περιμένετε το service **`A`** να στείλει ένα message που αναμένει reply.
2. Αντί να απαντήσετε απευθείας στο **`A`**, το reply port γίνεται hijack και χρησιμοποιείται για την αποστολή ενός message στο service **`B`**.
3. Στη συνέχεια, γίνεται dispatch ένα message που περιλαμβάνει την απαγορευμένη action, με την προσδοκία ότι θα υποβληθεί σε επεξεργασία concurrently με το reply από το **`B`**.<sup>[1]</sup>

Παρακάτω παρουσιάζεται μια οπτική αναπαράσταση του περιγραφόμενου attack scenario:

!\[https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/variant2.png]\(../../../../../../images/image (1) (1) (1) (1) (1) (1) (1).png)

<figure><img src="../../../../../../images/image (33).png" alt="https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/variant2.png" width="563"><figcaption></figcaption></figure>

## Προβλήματα Discovery

- **Δυσκολίες στον εντοπισμό instances**: Η αναζήτηση instances χρήσης του `xpc_connection_get_audit_token` ήταν δύσκολη, τόσο statically όσο και dynamically.
- **Methodology**: Χρησιμοποιήθηκε το Frida για hook στη function `xpc_connection_get_audit_token`, με filtering των calls που δεν προέρχονταν από event handlers. Ωστόσο, αυτή η μέθοδος περιοριζόταν στη hooked process και απαιτούσε ενεργή χρήση.
- **Analysis Tooling**: Tools όπως τα IDA/Ghidra χρησιμοποιήθηκαν για την εξέταση reachable mach services, αλλά η διαδικασία ήταν χρονοβόρα και περίπλοκη λόγω των calls που περιλάμβαναν το dyld shared cache.
- **Scripting Limitations**: Οι προσπάθειες δημιουργίας script για την ανάλυση calls προς το `xpc_connection_get_audit_token` από `dispatch_async` blocks παρεμποδίστηκαν από την πολυπλοκότητα του parsing των blocks και των interactions με το dyld shared cache.<sup>[1]</sup>

## Η διόρθωση <a href="#the-fix" id="the-fix"></a>

- **Reported Issues**: Υποβλήθηκε report στην Apple με λεπτομέρειες για τα γενικά και συγκεκριμένα issues που εντοπίστηκαν στο `smd`.
- **Apple's Response**: Η Apple αντιμετώπισε το issue στο `smd`, αντικαθιστώντας το `xpc_connection_get_audit_token` με το `xpc_dictionary_get_audit_token`.<sup>[1][2]</sup>
- **Nature of the Fix**: Η function `xpc_dictionary_get_audit_token` θεωρείται secure, καθώς ανακτά το audit token απευθείας από το mach message που συνδέεται με το XPC message που λήφθηκε. Ωστόσο, δεν αποτελεί μέρος του public API, όπως και το `xpc_connection_get_audit_token`.
- **Absence of a Broader Fix**: Παραμένει ασαφές γιατί η Apple δεν υλοποίησε μια πιο comprehensive fix, όπως το να απορρίπτει messages που δεν αντιστοιχούν στο αποθηκευμένο audit token της connection. Η πιθανότητα νόμιμων αλλαγών audit token σε ορισμένα scenarios (π.χ. χρήση `setuid`) ενδέχεται να αποτελεί παράγοντα.
- **Current Status**: Το issue παραμένει σε iOS 17 και macOS 14, δημιουργώντας πρόκληση για όσους προσπαθούν να το εντοπίσουν και να το κατανοήσουν.<sup>[1]</sup>

## Εντοπισμός vulnerable code paths στην πράξη (2024–2025)

Κατά το auditing XPC services για αυτήν την κατηγορία bug, εστιάστε σε authorization που εκτελείται εκτός του event handler του message ή concurrently με το reply processing.

Συμβουλές για static triage:
- Αναζητήστε calls προς το `xpc_connection_get_audit_token` που είναι reachable από blocks τα οποία γίνονται queued μέσω `dispatch_async`/`dispatch_after` ή άλλων worker queues που εκτελούνται εκτός του message handler.
- Αναζητήστε authorization helpers που συνδυάζουν per-connection και per-message state (π.χ. λήψη του PID από το `xpc_connection_get_pid`, αλλά του audit token από το `xpc_connection_get_audit_token`).
- Σε κώδικα NSXPC, επαληθεύστε ότι οι checks γίνονται στο `-listener:shouldAcceptNewConnection:` ή, για per-message checks, ότι η υλοποίηση χρησιμοποιεί per-message audit token (π.χ. το dictionary του message μέσω του `xpc_dictionary_get_audit_token` σε lower-level code).

Συμβουλές για dynamic triage:
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
- Για reply-forwarding races (Variant 2), παρακολουθήστε την ταυτόχρονη parsing των reply packets, fuzzing τα timings των `xpc_connection_send_message_with_reply` έναντι των κανονικών requests και ελέγχοντας αν το effective audit token που χρησιμοποιείται κατά την authorization μπορεί να επηρεαστεί.

## Exploitation primitives που πιθανότατα θα χρειαστείτε

- Multi-sender setup (Variant 1): δημιουργήστε connections προς τα A και B· κάντε duplicate το send right του client port του A και χρησιμοποιήστε το ως client port του B, ώστε τα replies του B να παραδίδονται στο A.
```c
// Duplicate a SEND right you already hold
mach_port_t dup;
mach_port_insert_right(mach_task_self(), a_client, a_client, MACH_MSG_TYPE_MAKE_SEND);
dup = a_client; // use `dup` when crafting B’s connect packet instead of a fresh client port
```
- Reply hijack (Variant 2): capture το send-once right από το pending request του A (reply port) και, στη συνέχεια, στείλε ένα crafted message στο B χρησιμοποιώντας αυτό το reply port, ώστε η απάντηση του B να καταλήξει στο A ενώ το privileged request σου γίνεται parse.

Αυτά απαιτούν low-level mach message crafting για τα XPC bootstrap και message formats. Δες τις σελίδες mach/XPC primer αυτής της ενότητας για τα ακριβή packet layouts και flags.

## Χρήσιμα εργαλεία

- XPC sniffing/dynamic inspection: το gxpc (open-source XPC sniffer) μπορεί να βοηθήσει στην απαρίθμηση connections και στην παρατήρηση traffic, ώστε να επικυρώσεις multi-sender setups και timing. Παράδειγμα: `gxpc -p <PID> --whitelist <service-name>`.
- Classic dyld interposing για το libxpc: κάνε interpose στα `xpc_connection_send_message*` και `xpc_connection_get_audit_token`, ώστε να καταγράφεις call sites και stacks κατά τη διάρκεια black-box testing.



## References

- [1] [Sector 7 – Don’t Talk All at Once! Elevating Privileges on macOS by Audit Token Spoofing](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)
- [2] [Apple – About the security content of macOS Ventura 13.4 (CVE‑2023‑32405)](https://support.apple.com/en-us/106333)


{{#include ../../../../../../banners/hacktricks-training.md}}
