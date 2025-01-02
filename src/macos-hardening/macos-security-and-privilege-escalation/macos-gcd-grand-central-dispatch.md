# macOS GCD - Grand Central Dispatch

{{#include ../../banners/hacktricks-training.md}}

## Basic Information

**Grand Central Dispatch (GCD),** επίσης γνωστό ως **libdispatch** (`libdispatch.dyld`), είναι διαθέσιμο τόσο σε macOS όσο και σε iOS. Είναι μια τεχνολογία που αναπτύχθηκε από την Apple για να βελτιστοποιήσει την υποστήριξη εφαρμογών για ταυτόχρονη (multithreaded) εκτέλεση σε υλικό πολλαπλών πυρήνων.

**GCD** παρέχει και διαχειρίζεται **FIFO queues** στις οποίες η εφαρμογή σας μπορεί να **υποβάλει εργασίες** με τη μορφή **block objects**. Τα blocks που υποβάλλονται σε dispatch queues εκτελούνται σε μια πισίνα νημάτων που διαχειρίζεται πλήρως το σύστημα. Το GCD δημιουργεί αυτόματα νήματα για την εκτέλεση των εργασιών στις dispatch queues και προγραμματίζει αυτές τις εργασίες να εκτελούνται στους διαθέσιμους πυρήνες.

> [!TIP]
> Συνοπτικά, για να εκτελέσετε κώδικα **παράλληλα**, οι διεργασίες μπορούν να στείλουν **blocks κώδικα στο GCD**, το οποίο θα φροντίσει για την εκτέλεσή τους. Επομένως, οι διεργασίες δεν δημιουργούν νέα νήματα; **Το GCD εκτελεί τον δεδομένο κώδικα με τη δική του πισίνα νημάτων** (η οποία μπορεί να αυξάνεται ή να μειώνεται ανάλογα με τις ανάγκες).

Αυτό είναι πολύ χρήσιμο για τη διαχείριση της παράλληλης εκτέλεσης με επιτυχία, μειώνοντας σημαντικά τον αριθμό των νημάτων που δημιουργούν οι διεργασίες και βελτιστοποιώντας την παράλληλη εκτέλεση. Αυτό είναι ιδανικό για εργασίες που απαιτούν **μεγάλο παράλληλο** (brute-forcing?) ή για εργασίες που δεν θα πρέπει να μπλοκάρουν το κύριο νήμα: Για παράδειγμα, το κύριο νήμα στο iOS διαχειρίζεται τις αλληλεπιδράσεις UI, οπότε οποιαδήποτε άλλη λειτουργικότητα που θα μπορούσε να κάνει την εφαρμογή να κολλήσει (αναζήτηση, πρόσβαση στο διαδίκτυο, ανάγνωση αρχείου...) διαχειρίζεται με αυτόν τον τρόπο.

### Blocks

Ένα block είναι μια **αυτοτελής ενότητα κώδικα** (όπως μια συνάρτηση με παραμέτρους που επιστρέφει μια τιμή) και μπορεί επίσης να καθορίσει δεσμευμένες μεταβλητές.\
Ωστόσο, σε επίπεδο μεταγλωττιστή, τα blocks δεν υπάρχουν, είναι `os_object`s. Κάθε ένα από αυτά τα αντικείμενα σχηματίζεται από δύο δομές:

- **block literal**:&#x20;
- Ξεκινά από το πεδίο **`isa`**, που δείχνει στην κλάση του block:
- `NSConcreteGlobalBlock` (blocks από `__DATA.__const`)
- `NSConcreteMallocBlock` (blocks στο heap)
- `NSConcreateStackBlock` (blocks στο stack)
- Έχει **`flags`** (που υποδεικνύουν τα πεδία που υπάρχουν στον περιγραφέα του block) και μερικά δεσμευμένα bytes
- Ο δείκτης συνάρτησης για κλήση
- Ένας δείκτης στον περιγραφέα του block
- Εισαγόμενες μεταβλητές block (αν υπάρχουν)
- **block descriptor**: Το μέγεθός του εξαρτάται από τα δεδομένα που είναι παρόντα (όπως υποδεικνύεται στα προηγούμενα flags)
- Έχει μερικά δεσμευμένα bytes
- Το μέγεθός του
- Συνήθως θα έχει έναν δείκτη σε μια υπογραφή στυλ Objective-C για να γνωρίζει πόσο χώρο χρειάζεται για τις παραμέτρους (flag `BLOCK_HAS_SIGNATURE`)
- Αν οι μεταβλητές αναφέρονται, αυτό το block θα έχει επίσης δείκτες σε έναν βοηθό αντιγραφής (αντιγράφοντας την τιμή στην αρχή) και σε έναν βοηθό απελευθέρωσης (απελευθερώνοντάς την).

### Queues

Μια dispatch queue είναι ένα ονομαστικό αντικείμενο που παρέχει FIFO διάταξη των blocks για εκτέλεση.

Τα blocks τοποθετούνται σε queues για εκτέλεση, και αυτές υποστηρίζουν 2 λειτουργίες: `DISPATCH_QUEUE_SERIAL` και `DISPATCH_QUEUE_CONCURRENT`. Φυσικά, η **σειριακή** δεν θα έχει προβλήματα **race condition** καθώς ένα block δεν θα εκτελείται μέχρι να έχει ολοκληρωθεί το προηγούμενο. Αλλά **ο άλλος τύπος queue μπορεί να έχει**.

Προεπιλεγμένες queues:

- `.main-thread`: Από `dispatch_get_main_queue()`
- `.libdispatch-manager`: Διαχειριστής queue του GCD
- `.root.libdispatch-manager`: Διαχειριστής queue του GCD
- `.root.maintenance-qos`: Εργασίες χαμηλότερης προτεραιότητας
- `.root.maintenance-qos.overcommit`
- `.root.background-qos`: Διαθέσιμο ως `DISPATCH_QUEUE_PRIORITY_BACKGROUND`
- `.root.background-qos.overcommit`
- `.root.utility-qos`: Διαθέσιμο ως `DISPATCH_QUEUE_PRIORITY_NON_INTERACTIVE`
- `.root.utility-qos.overcommit`
- `.root.default-qos`: Διαθέσιμο ως `DISPATCH_QUEUE_PRIORITY_DEFAULT`
- `.root.background-qos.overcommit`
- `.root.user-initiated-qos`: Διαθέσιμο ως `DISPATCH_QUEUE_PRIORITY_HIGH`
- `.root.background-qos.overcommit`
- `.root.user-interactive-qos`: Υψηλότερη προτεραιότητα
- `.root.background-qos.overcommit`

Σημειώστε ότι θα είναι το σύστημα που θα αποφασίσει **ποια νήματα θα διαχειρίζονται ποιες queues κάθε στιγμή** (πολλαπλά νήματα μπορεί να εργάζονται στην ίδια queue ή το ίδιο νήμα μπορεί να εργάζεται σε διαφορετικές queues σε κάποια στιγμή)

#### Attributtes

Όταν δημιουργείτε μια queue με **`dispatch_queue_create`** το τρίτο επιχείρημα είναι ένα `dispatch_queue_attr_t`, το οποίο συνήθως είναι είτε `DISPATCH_QUEUE_SERIAL` (το οποίο είναι στην πραγματικότητα NULL) είτε `DISPATCH_QUEUE_CONCURRENT` που είναι ένας δείκτης σε μια δομή `dispatch_queue_attr_t` που επιτρέπει τον έλεγχο ορισμένων παραμέτρων της queue.

### Dispatch objects

Υπάρχουν διάφορα αντικείμενα που χρησιμοποιεί το libdispatch και οι queues και τα blocks είναι μόνο 2 από αυτά. Είναι δυνατή η δημιουργία αυτών των αντικειμένων με `dispatch_object_create`:

- `block`
- `data`: Δεδομένα blocks
- `group`: Ομάδα blocks
- `io`: Async I/O αιτήματα
- `mach`: Mach ports
- `mach_msg`: Mach μηνύματα
- `pthread_root_queue`: Μια queue με μια πισίνα νημάτων pthread και όχι workqueues
- `queue`
- `semaphore`
- `source`: Πηγή γεγονότων

## Objective-C

Στην Objective-C υπάρχουν διάφορες συναρτήσεις για την αποστολή ενός block για εκτέλεση παράλληλα:

- [**dispatch_async**](https://developer.apple.com/documentation/dispatch/1453057-dispatch_async): Υποβάλλει ένα block για ασύγχρονη εκτέλεση σε μια dispatch queue και επιστρέφει αμέσως.
- [**dispatch_sync**](https://developer.apple.com/documentation/dispatch/1452870-dispatch_sync): Υποβάλλει ένα block object για εκτέλεση και επιστρέφει μετά την ολοκλήρωση της εκτέλεσης αυτού του block.
- [**dispatch_once**](https://developer.apple.com/documentation/dispatch/1447169-dispatch_once): Εκτελεί ένα block object μόνο μία φορά για τη διάρκεια ζωής μιας εφαρμογής.
- [**dispatch_async_and_wait**](https://developer.apple.com/documentation/dispatch/3191901-dispatch_async_and_wait): Υποβάλλει ένα εργασία για εκτέλεση και επιστρέφει μόνο μετά την ολοκλήρωση της εκτέλεσης. Σε αντίθεση με [**`dispatch_sync`**](https://developer.apple.com/documentation/dispatch/1452870-dispatch_sync), αυτή η συνάρτηση σέβεται όλα τα χαρακτηριστικά της queue όταν εκτελεί το block.

Αυτές οι συναρτήσεις αναμένουν αυτές τις παραμέτρους: [**`dispatch_queue_t`**](https://developer.apple.com/documentation/dispatch/dispatch_queue_t) **`queue,`** [**`dispatch_block_t`**](https://developer.apple.com/documentation/dispatch/dispatch_block_t) **`block`**

Αυτή είναι η **δομή ενός Block**:
```c
struct Block {
void *isa; // NSConcreteStackBlock,...
int flags;
int reserved;
void *invoke;
struct BlockDescriptor *descriptor;
// captured variables go here
};
```
Και αυτό είναι ένα παράδειγμα χρήσης του **parallelism** με **`dispatch_async`**:
```objectivec
#import <Foundation/Foundation.h>

// Define a block
void (^backgroundTask)(void) = ^{
// Code to be executed in the background
for (int i = 0; i < 10; i++) {
NSLog(@"Background task %d", i);
sleep(1);  // Simulate a long-running task
}
};

int main(int argc, const char * argv[]) {
@autoreleasepool {
// Create a dispatch queue
dispatch_queue_t backgroundQueue = dispatch_queue_create("com.example.backgroundQueue", NULL);

// Submit the block to the queue for asynchronous execution
dispatch_async(backgroundQueue, backgroundTask);

// Continue with other work on the main queue or thread
for (int i = 0; i < 10; i++) {
NSLog(@"Main task %d", i);
sleep(1);  // Simulate a long-running task
}
}
return 0;
}
```
## Swift

**`libswiftDispatch`** είναι μια βιβλιοθήκη που παρέχει **Swift bindings** στο πλαίσιο Grand Central Dispatch (GCD) το οποίο είναι αρχικά γραμμένο σε C.\
Η βιβλιοθήκη **`libswiftDispatch`** περιτυλίγει τα C GCD APIs σε μια πιο φιλική προς το Swift διεπαφή, διευκολύνοντας και καθιστώντας πιο διαισθητική τη δουλειά των προγραμματιστών Swift με το GCD.

- **`DispatchQueue.global().sync{ ... }`**
- **`DispatchQueue.global().async{ ... }`**
- **`let onceToken = DispatchOnce(); onceToken.perform { ... }`**
- **`async await`**
- **`var (data, response) = await URLSession.shared.data(from: URL(string: "https://api.example.com/getData"))`**

**Code example**:
```swift
import Foundation

// Define a closure (the Swift equivalent of a block)
let backgroundTask: () -> Void = {
for i in 0..<10 {
print("Background task \(i)")
sleep(1)  // Simulate a long-running task
}
}

// Entry point
autoreleasepool {
// Create a dispatch queue
let backgroundQueue = DispatchQueue(label: "com.example.backgroundQueue")

// Submit the closure to the queue for asynchronous execution
backgroundQueue.async(execute: backgroundTask)

// Continue with other work on the main queue
for i in 0..<10 {
print("Main task \(i)")
sleep(1)  // Simulate a long-running task
}
}
```
## Frida

Το παρακάτω σενάριο Frida μπορεί να χρησιμοποιηθεί για να **συνδεθεί σε πολλές `dispatch`** συναρτήσεις και να εξάγει το όνομα της ουράς, το backtrace και το block: [**https://github.com/seemoo-lab/frida-scripts/blob/main/scripts/libdispatch.js**](https://github.com/seemoo-lab/frida-scripts/blob/main/scripts/libdispatch.js)
```bash
frida -U <prog_name> -l libdispatch.js

dispatch_sync
Calling queue: com.apple.UIKit._UIReusePool.reuseSetAccess
Callback function: 0x19e3a6488 UIKitCore!__26-[_UIReusePool addObject:]_block_invoke
Backtrace:
0x19e3a6460 UIKitCore!-[_UIReusePool addObject:]
0x19e3a5db8 UIKitCore!-[UIGraphicsRenderer _enqueueContextForReuse:]
0x19e3a57fc UIKitCore!+[UIGraphicsRenderer _destroyCGContext:withRenderer:]
[...]
```
## Ghidra

Αυτή τη στιγμή, το Ghidra δεν κατανοεί ούτε τη δομή ObjectiveC **`dispatch_block_t`**, ούτε τη **`swift_dispatch_block`**.

Έτσι, αν θέλετε να την κατανοήσει, μπορείτε απλά να **τις δηλώσετε**:

<figure><img src="../../images/image (1160).png" alt="" width="563"><figcaption></figcaption></figure>

<figure><img src="../../images/image (1162).png" alt="" width="563"><figcaption></figcaption></figure>

<figure><img src="../../images/image (1163).png" alt="" width="563"><figcaption></figcaption></figure>

Στη συνέχεια, βρείτε ένα μέρος στον κώδικα όπου **χρησιμοποιούνται**:

> [!TIP]
> Σημειώστε όλες τις αναφορές που γίνονται στο "block" για να κατανοήσετε πώς μπορείτε να καταλάβετε ότι η δομή χρησιμοποιείται.

<figure><img src="../../images/image (1164).png" alt="" width="563"><figcaption></figcaption></figure>

Κάντε δεξί κλικ στη μεταβλητή -> Επανατύπωση Μεταβλητής και επιλέξτε σε αυτή την περίπτωση **`swift_dispatch_block`**:

<figure><img src="../../images/image (1165).png" alt="" width="563"><figcaption></figcaption></figure>

Το Ghidra θα ξαναγράψει αυτόματα τα πάντα:

<figure><img src="../../images/image (1166).png" alt="" width="563"><figcaption></figcaption></figure>

## References

- [**\*OS Internals, Volume I: User Mode. By Jonathan Levin**](https://www.amazon.com/MacOS-iOS-Internals-User-Mode/dp/099105556X)

{{#include ../../banners/hacktricks-training.md}}
