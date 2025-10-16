# macOS xpc_connection_get_audit_token Επίθεση

{{#include ../../../../../../banners/hacktricks-training.md}}

**Για περισσότερες πληροφορίες ελέγξτε την αρχική ανάρτηση:** [**https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/**](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/). Αυτή είναι μια περίληψη:

## Mach Messages Basic Info

Εάν δεν ξέρετε τι είναι τα Mach Messages ξεκινήστε ελέγχοντας αυτή τη σελίδα:


{{#ref}}
../../
{{#endref}}

Προς το παρόν θυμηθείτε ότι ([definition from here](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing)):\
Τα Mach messages αποστέλλονται μέσω ενός _mach port_, το οποίο είναι ένα κανάλι επικοινωνίας **single receiver, multiple sender** ενσωματωμένο στον mach kernel. **Πολλές διεργασίες μπορούν να στείλουν μηνύματα** σε ένα mach port, αλλά ανά πάσα στιγμή **μόνο μία διεργασία μπορεί να διαβάσει από αυτό**. Όπως τα file descriptors και τα sockets, τα mach ports διατίθενται και διαχειρίζονται από τον kernel και οι διεργασίες βλέπουν μόνο έναν ακέραιο, που μπορούν να χρησιμοποιήσουν για να υποδείξουν στον kernel ποιο από τα mach ports τους θέλουν να χρησιμοποιήσουν.

## XPC Connection

Εάν δεν γνωρίζετε πώς γίνεται η δημιουργία μιας σύνδεσης XPC δείτε:


{{#ref}}
../
{{#endref}}

## Vuln Summary

Είναι χρήσιμο να γνωρίζετε ότι η abstraction του XPC είναι μια σύνδεση one-to-one, αλλά βασίζεται πάνω σε μια τεχνολογία που μπορεί να έχει multiple senders, οπότε:

- Τα Mach ports είναι single receiver, **multiple sender**.
- Το audit token μιας XPC connection είναι το audit token που **αντιγράφεται από το πιο πρόσφατα ληφθέν μήνυμα**.
- Η απόκτηση του **audit token** μιας XPC connection είναι κρίσιμη για πολλούς **έλεγχους ασφαλείας**.

Αν και η παραπάνω κατάσταση φαίνεται προβληματική, υπάρχουν σενάρια όπου αυτό δεν θα προκαλέσει προβλήματα ([from here](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing)):

- Τα audit tokens συχνά χρησιμοποιούνται για έναν έλεγχο εξουσιοδότησης για να αποφασίσουν αν θα αποδεχτούν μια σύνδεση. Καθώς αυτό γίνεται χρησιμοποιώντας ένα μήνυμα προς το service port, **δεν υπάρχει ακόμη καθορισμένη σύνδεση**. Περισσότερα μηνύματα σε αυτή την πόρτα απλά θα χειριστούν ως πρόσθετα αιτήματα σύνδεσης. Οπότε οποιοιδήποτε **έλεγχοι πριν την αποδοχή μιας σύνδεσης δεν είναι ευάλωτοι** (αυτό σημαίνει επίσης ότι μέσα σε `-listener:shouldAcceptNewConnection:` το audit token είναι ασφαλές). Αναζητούμε λοιπόν **XPC connections που επαληθεύουν συγκεκριμένες ενέργειες**.
- Οι XPC event handlers χειρίζονται συγχρονισμένα. Αυτό σημαίνει ότι ο event handler για ένα μήνυμα πρέπει να ολοκληρωθεί πριν κληθεί για το επόμενο, ακόμα και σε concurrent dispatch queues. Επομένως, μέσα σε έναν **XPC event handler το audit token δεν μπορεί να αντικατασταθεί** από άλλα κανονικά (μη-reply!) μηνύματα.

Δύο διαφορετικές μέθοδοι που αυτό μπορεί να είναι εκμεταλλεύσιμο:

1. Variant1:
- Το **Exploit** **connects** στο service **A** και στο service **B**
- Το Service **B** μπορεί να καλέσει μια **privileged functionality** στο service A που ο χρήστης δεν μπορεί
- Το Service **A** καλεί **`xpc_connection_get_audit_token`** ενώ _**δεν**_ βρίσκεται μέσα στον **event handler** για μια σύνδεση, αλλά σε ένα **`dispatch_async`**.
- Έτσι, ένα **διαφορετικό** μήνυμα θα μπορούσε να **επαναγράψει το Audit Token** επειδή γίνεται dispatch ασύγχρονα εκτός του event handler.
- Το exploit περνάει στο **service B** το SEND right του service **A**.
- Οπότε το svc **B** θα στέλνει πρακτικά τα **μηνύματα** στο service **A**.
- Το **exploit** προσπαθεί να **καλέσει** τη **privileged action.** Σε μια RC το svc **A** **ελέγχει** την εξουσιοδότηση αυτής της **ενέργειας** ενώ **svc B έχει αντικαταστήσει το Audit token** (δίνοντας στο exploit πρόσβαση να καλέσει την privileged ενέργεια).
2. Variant 2:
- Το Service **B** μπορεί να καλέσει μια **privileged functionality** στο service A που ο χρήστης δεν μπορεί
- Το Exploit συνδέεται με το **service A** το οποίο **στέλνει** στο exploit ένα **μήνυμα που αναμένει απάντηση** σε μια συγκεκριμένη **reply** **port**.
- Το Exploit στέλνει στο **service B** ένα μήνυμα περνώντας **εκείνη την reply port**.
- Όταν το service **B** απαντήσει, στέλνει το μήνυμα στο service **A**, **ενώ** το **exploit** στέλνει διαφορετικό **μήνυμα στο service A** προσπαθώντας να **προσεγγίσει μια privileged functionality** και αναμένοντας ότι η απάντηση από το service B θα αντικαταστήσει το Audit token τη σωστή στιγμή (Race Condition).

## Variant 1: calling xpc_connection_get_audit_token outside of an event handler <a href="#variant-1-calling-xpc_connection_get_audit_token-outside-of-an-event-handler" id="variant-1-calling-xpc_connection_get_audit_token-outside-of-an-event-handler"></a>

Σενάριο:

- Δύο mach services **`A`** και **`B`** στα οποία μπορούμε και οι δύο να συνδεθούμε (βασισμένο στο sandbox profile και τους ελέγχους εξουσιοδότησης πριν την αποδοχή της σύνδεσης).
- Ο _**A**_ πρέπει να έχει έναν **έλεγχο εξουσιοδότησης** για μια συγκεκριμένη ενέργεια που **`B`** μπορεί να περάσει (αλλά η εφαρμογή μας όχι).
- Για παράδειγμα, αν το B έχει κάποια **entitlements** ή τρέχει ως **root**, μπορεί να του επιτρέπει να ζητήσει από το A να εκτελέσει μια privileged ενέργεια.
- Για αυτόν τον έλεγχο εξουσιοδότησης, το **`A`** παίρνει το audit token ασύγχρονα, για παράδειγμα καλώντας `xpc_connection_get_audit_token` από **`dispatch_async`**.

> [!CAUTION]
> Σε αυτή την περίπτωση ένας attacker θα μπορούσε να προκαλέσει ένα **Race Condition** δημιουργώντας ένα **exploit** που **ζητά από το A να εκτελέσει μια ενέργεια** πολλές φορές ενώ κάνει **B να στέλνει μηνύματα στο `A`**. Όταν η RC είναι **επιτυχής**, το **audit token** του **B** θα αντιγραφεί στη μνήμη **ενώ** το αίτημα του **exploit** χειρίζεται από το A, δίνοντας σε αυτό **πρόσβαση στην privileged ενέργεια που μόνο το B θα μπορούσε να ζητήσει**.

Αυτό συνέβη με το **`A`** ως `smd` και το **`B`** ως `diagnosticd`. Η συνάρτηση [`SMJobBless`](https://developer.apple.com/documentation/servicemanagement/1431078-smjobbless?language=objc) από smb μπορεί να χρησιμοποιηθεί για να εγκαταστήσει ένα νέο privileged helper tool (ως **root**). Αν μια **process που τρέχει ως root επικοινωνήσει** με το **smd**, δεν θα γίνουν άλλοι έλεγχοι.

Επομένως, το service **B** είναι **`diagnosticd`** επειδή τρέχει ως **root** και μπορεί να χρησιμοποιηθεί για να **monitor** μια διεργασία, έτσι μόλις ξεκινήσει το monitoring, θα **στέλνει πολλαπλά μηνύματα ανά δευτερόλεπτο.**

Για να εκτελέσετε την επίθεση:

1. Ξεκινήστε μια **σύνδεση** προς το service με όνομα `smd` χρησιμοποιώντας το standard XPC protocol.
2. Δημιουργήστε μια δευτερεύουσα **σύνδεση** προς το `diagnosticd`. Αντί για την κανονική διαδικασία, αντί να δημιουργηθούν και να αποσταλούν δύο νέα mach ports, το client port send right αντικαθίσταται με ένα αντίγραφο του **send right** που σχετίζεται με τη σύνδεση `smd`.
3. Ως αποτέλεσμα, XPC μηνύματα μπορούν να διαβιβαστούν στο `diagnosticd`, αλλά οι απαντήσεις από το `diagnosticd` παρακάμπτονται προς το `smd`. Για το `smd`, φαίνεται σαν τα μηνύματα τόσο από τον χρήστη όσο και από το `diagnosticd` να προέρχονται από την ίδια σύνδεση.

![Εικόνα που περιγράφει τη διαδικασία του exploit](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/exploit.png)

4. Το επόμενο βήμα περιλαμβάνει την εντολή στο `diagnosticd` να ξεκινήσει monitoring μιας επιλεγμένης διεργασίας (πιθανώς της δικής του εφαρμογής). Ταυτόχρονα, στέλνεται ένας κατακλυσμός από ρουτίνες 1004 μηνυμάτων στο `smd`. Ο σκοπός εδώ είναι να εγκατασταθεί ένα εργαλείο με αυξημένα προνόμια.
5. Αυτή η ενέργεια πυροδοτεί ένα race condition μέσα στη συνάρτηση `handle_bless`. Ο χρονισμός είναι κρίσιμος: η κλήση της `xpc_connection_get_pid` πρέπει να επιστρέψει το PID της διεργασίας του χρήστη (εφόσον το privileged tool βρίσκεται στο user app bundle). Ωστόσο, η `xpc_connection_get_audit_token` συγκεκριμένα, εντός της υπορουτίνας `connection_is_authorized`, πρέπει να αναφέρεται στο audit token που ανήκει στο `diagnosticd`.

## Variant 2: reply forwarding

Σε ένα XPC (Cross-Process Communication) περιβάλλον, αν και οι event handlers δεν τρέχουν ταυτόχρονα, ο χειρισμός των reply μηνυμάτων έχει μια μοναδική συμπεριφορά. Συγκεκριμένα, υπάρχουν δύο διακριτοί τρόποι για την αποστολή μηνυμάτων που αναμένουν απάντηση:

1. **`xpc_connection_send_message_with_reply`**: Εδώ, το XPC μήνυμα λαμβάνεται και επεξεργάζεται σε μια καθορισμένη queue.
2. **`xpc_connection_send_message_with_reply_sync`**: Αντίθετα, σε αυτή τη μέθοδο, το XPC μήνυμα λαμβάνεται και επεξεργάζεται στην τρέχουσα dispatch queue.

Αυτή η διάκριση είναι κρίσιμη επειδή επιτρέπει την πιθανότητα για **reply packets να αναλυθούν ταυτόχρονα με την εκτέλεση ενός XPC event handler**. Σημειωτέον, ενώ `_xpc_connection_set_creds` εφαρμόζει locking για να προστατεύσει από μερική επανεγγραφή του audit token, δεν επεκτείνει αυτή την προστασία σε ολόκληρο το αντικείμενο σύνδεσης. Επομένως, αυτό δημιουργεί μια ευπάθεια όπου το audit token μπορεί να αντικατασταθεί στο διάστημα μεταξύ της ανάλυσης ενός πακέτου και της εκτέλεσης του event handler του.

Για να εκμεταλλευτείτε αυτή την ευπάθεια απαιτείται το ακόλουθο setup:

- Δύο mach services, αναφερόμενα ως **`A`** και **`B`**, και τα δύο μπορούν να δημιουργήσουν σύνδεση.
- Το service **`A`** θα πρέπει να περιλαμβάνει έναν έλεγχο εξουσιοδότησης για μια συγκεκριμένη ενέργεια που μόνο το **`B`** μπορεί να πραγματοποιήσει (η εφαρμογή του χρήστη δεν μπορεί).
- Το service **`A`** θα πρέπει να στείλει ένα μήνυμα που αναμένει απάντηση.
- Ο χρήστης μπορεί να στείλει ένα μήνυμα στο **`B`** στο οποίο αυτό θα απαντήσει.

Η διαδικασία εκμετάλλευσης περιλαμβάνει τα εξής βήματα:

1. Περιμένετε το service **`A`** να στείλει ένα μήνυμα που περιμένει απάντηση.
2. Αντί να απαντήσετε απευθείας στο **`A`**, η reply port υπεξαιρείται και χρησιμοποιείται για να σταλεί ένα μήνυμα στο service **`B`**.
3. Στη συνέχεια, αποστέλλεται ένα μήνυμα που αφορά την απαγορευμένη ενέργεια, με την προσδοκία ότι θα επεξεργαστεί ταυτόχρονα με την απάντηση από το **`B`**.

Below is a visual representation of the described attack scenario:

!\[https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/variant2.png]\(../../../../../../images/image (1) (1) (1) (1) (1) (1) (1).png)

<figure><img src="../../../../../../images/image (33).png" alt="https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/variant2.png" width="563"><figcaption></figcaption></figure>

## Discovery Problems

- **Δυσκολίες στην Εντοπισμό Περιπτώσεων**: Η αναζήτηση για περιπτώσεις χρήσης του `xpc_connection_get_audit_token` ήταν δύσκολη, τόσο στατικά όσο και δυναμικά.
- **Μεθοδολογία**: Χρησιμοποιήθηκε Frida για να γίνει hook στη συνάρτηση `xpc_connection_get_audit_token`, φιλτράροντας κλήσεις που δεν προέρχονταν από event handlers. Ωστόσο, αυτή η μέθοδος περιοριζόταν στη hooked process και απαιτούσε ενεργή χρήση.
- **Εργαλεία Ανάλυσης**: Εργαλεία όπως IDA/Ghidra χρησιμοποιήθηκαν για την εξέταση reachable mach services, αλλά η διαδικασία ήταν χρονοβόρα, περίπλοκη λόγω κλήσεων που εμπλέκουν το dyld shared cache.
- **Περιορισμοί Σκριπτινγκ**: Οι προσπάθειες να αυτοματοποιηθεί η ανάλυση για κλήσεις σε `xpc_connection_get_audit_token` μέσα σε `dispatch_async` blocks επηρεάστηκαν από την πολυπλοκότητα στην ανάλυση των blocks και τις αλληλεπιδράσεις με το dyld shared cache.

## The fix <a href="#the-fix" id="the-fix"></a>

- **Αναφερόμενα Θέματα**: Υποβλήθηκε αναφορά στην Apple που περιέγραφε τα γενικά και ειδικά ζητήματα που βρέθηκαν στο `smd`.
- **Απάντηση της Apple**: Η Apple επιδιόρθωσε το ζήτημα στο `smd` αντικαθιστώντας το `xpc_connection_get_audit_token` με `xpc_dictionary_get_audit_token`.
- **Φύση της Διόρθωσης**: Η `xpc_dictionary_get_audit_token` θεωρείται ασφαλής καθώς ανακτά το audit token απευθείας από το mach message που σχετίζεται με το ληφθέν XPC μήνυμα. Ωστόσο, δεν αποτελεί μέρος του δημόσιου API, παρόμοια με το `xpc_connection_get_audit_token`.
- **Έλλειψη Ευρύτερης Διόρθωσης**: Δεν είναι σαφές γιατί η Apple δεν εφάρμοσε μια πιο γενική διόρθωση, όπως η απόρριψη μηνυμάτων που δεν συμφωνούν με το αποθηκευμένο audit token της σύνδεσης. Η πιθανότητα νόμιμων αλλαγών audit token σε ορισμένα σενάρια (π.χ. χρήση `setuid`) μπορεί να αποτελεί παράγοντα.
- **Τρέχουσα Κατάσταση**: Το πρόβλημα εξακολουθεί να υπάρχει σε iOS 17 και macOS 14, καθιστώντας δύσκολο για όσους προσπαθούν να το εντοπίσουν και να το κατανοήσουν.

## Finding vulnerable code paths in practice (2024–2025)

Κατά τον έλεγχο υπηρεσιών XPC για αυτή την κατηγορία bug, επικεντρωθείτε σε εξουσιοδοτήσεις που εκτελούνται εκτός του event handler του μηνύματος ή ταυτόχρονα με την επεξεργασία replies.

Στατικά hints για τριάζ:
- Αναζητήστε κλήσεις σε `xpc_connection_get_audit_token` που είναι προσβάσιμες από blocks που τοποθετούνται μέσω `dispatch_async`/`dispatch_after` ή άλλων worker queues που τρέχουν εκτός του message handler.
- Ψάξτε για helpers εξουσιοδότησης που αναμειγνύουν per-connection και per-message κατάσταση (π.χ., παίρνουν PID από `xpc_connection_get_pid` αλλά audit token από `xpc_connection_get_audit_token`).
- Σε NSXPC κώδικα, επαληθεύστε ότι οι έλεγχοι γίνονται σε `-listener:shouldAcceptNewConnection:` ή, για per-message checks, ότι η υλοποίηση χρησιμοποιεί ένα per-message audit token (π.χ., το λεξικό του μηνύματος μέσω `xpc_dictionary_get_audit_token` σε χαμηλότερου επιπέδου κώδικα).

Δυναμικά tips για τριάζ:
- Κάντε hook σε `xpc_connection_get_audit_token` και σημαδέψτε κλήσεις των οποίων το user stack δεν περιλαμβάνει το event-delivery path (π.χ., `_xpc_connection_mach_event`). Παράδειγμα Frida hook:
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
- Στο macOS, η instrumenting προστατευμένων/Apple binaries μπορεί να απαιτεί το SIP να είναι απενεργοποιημένο ή ένα development environment· προτιμήστε να δοκιμάζετε τα δικά σας builds ή userland services.
- Για reply-forwarding races (Variant 2), παρακολουθήστε το ταυτόχρονο parsing των reply packets με fuzzing των timings του `xpc_connection_send_message_with_reply` έναντι κανονικών requests και ελέγξτε αν το effective audit token που χρησιμοποιείται κατά την authorization μπορεί να επηρεαστεί.

## Exploitation primitives που πιθανότατα θα χρειαστείτε

- Multi-sender setup (Variant 1): δημιουργήστε συνδέσεις προς A και B; αντιγράψτε το send right της client port του A και χρησιμοποιήστε το ως client port του B ώστε οι απαντήσεις του B να παραδίδονται στον A.
```c
// Duplicate a SEND right you already hold
mach_port_t dup;
mach_port_insert_right(mach_task_self(), a_client, a_client, MACH_MSG_TYPE_MAKE_SEND);
dup = a_client; // use `dup` when crafting B’s connect packet instead of a fresh client port
```
- Reply hijack (Variant 2): καταλάβετε το send-once right από το pending request του A (reply port), στη συνέχεια στείλτε ένα crafted message προς το B χρησιμοποιώντας εκείνο το reply port ώστε η απάντηση του B να καταλήξει στον A ενώ το privileged request σας επεξεργάζεται.

These require low-level mach message crafting for the XPC bootstrap and message formats; review the mach/XPC primer pages in this section for the exact packet layouts and flags.

## Χρήσιμα εργαλεία

- XPC sniffing/dynamic inspection: gxpc (open-source XPC sniffer) μπορεί να βοηθήσει στην καταγραφή συνδέσεων και στην παρατήρηση traffic για να επικυρώσετε multi-sender setups και timing. Example: `gxpc -p <PID> --whitelist <service-name>`.
- Classic dyld interposing for libxpc: interpose on `xpc_connection_send_message*` and `xpc_connection_get_audit_token` για να καταγράψετε call sites και stacks κατά τη διάρκεια black-box testing.



## References

- Sector 7 – Don’t Talk All at Once! Elevating Privileges on macOS by Audit Token Spoofing: <https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/>
- Apple – About the security content of macOS Ventura 13.4 (CVE‑2023‑32405): <https://support.apple.com/en-us/106333>


{{#include ../../../../../../banners/hacktricks-training.md}}
