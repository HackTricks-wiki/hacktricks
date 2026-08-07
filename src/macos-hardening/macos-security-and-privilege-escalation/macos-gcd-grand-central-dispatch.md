# macOS GCD - Grand Central Dispatch

{{#include ../../banners/hacktricks-training.md}}

## Βασικές πληροφορίες

Το **Grand Central Dispatch (GCD),** γνωστό επίσης ως **libdispatch** (`libdispatch.dyld`), είναι διαθέσιμο τόσο στο macOS όσο και στο iOS. Πρόκειται για τεχνολογία που αναπτύχθηκε από την Apple για τη βελτιστοποίηση της υποστήριξης εφαρμογών για ταυτόχρονη (multithreaded) εκτέλεση σε hardware με πολλαπλούς πυρήνες.<sup>[[4]](#references)</sup>

Το **GCD** παρέχει και διαχειρίζεται **FIFO queues**, στις οποίες η εφαρμογή σας μπορεί να **υποβάλλει tasks** με τη μορφή **block objects**. Τα blocks που υποβάλλονται σε dispatch queues **εκτελούνται σε ένα pool από threads**, το οποίο διαχειρίζεται πλήρως το σύστημα. Το GCD δημιουργεί αυτόματα threads για την εκτέλεση των tasks στις dispatch queues και προγραμματίζει αυτά τα tasks να εκτελεστούν στους διαθέσιμους πυρήνες.<sup>[[1]](#references)</sup>

> [!TIP]
> Συνοπτικά, για την εκτέλεση κώδικα **παράλληλα**, οι διεργασίες μπορούν να στέλνουν **blocks κώδικα στο GCD**, το οποίο αναλαμβάνει την εκτέλεσή τους. Επομένως, οι διεργασίες δεν δημιουργούν νέα threads· **το GCD εκτελεί τον δεδομένο κώδικα με το δικό του pool από threads** (το οποίο μπορεί να αυξάνεται ή να μειώνεται ανάλογα με τις ανάγκες).

Αυτό είναι πολύ χρήσιμο για την επιτυχή διαχείριση της παράλληλης εκτέλεσης, μειώνοντας σημαντικά τον αριθμό των threads που δημιουργούν οι διεργασίες και βελτιστοποιώντας την παράλληλη εκτέλεση. Είναι ιδανικό για tasks που απαιτούν **μεγάλο παραλληλισμό** (brute-forcing;) ή για tasks που δεν θα πρέπει να μπλοκάρουν το main thread: Για παράδειγμα, το main thread στο iOS διαχειρίζεται τις αλληλεπιδράσεις του UI, επομένως κάθε άλλη λειτουργικότητα που θα μπορούσε να κάνει την εφαρμογή να «κολλήσει» (αναζήτηση, πρόσβαση σε web, ανάγνωση αρχείου...) διαχειρίζεται με αυτόν τον τρόπο.

### Blocks

Ένα block είναι ένα **αυτοτελές τμήμα κώδικα** (όπως μια function με arguments που επιστρέφει μια τιμή) και μπορεί επίσης να καθορίζει bound variables.\
Ωστόσο, σε επίπεδο compiler τα blocks δεν υπάρχουν· είναι `os_object`s. Κάθε ένα από αυτά τα objects αποτελείται από δύο structures:

- **block literal**:
- Ξεκινά με το πεδίο **`isa`**, το οποίο δείχνει στην class του block:
- `NSConcreteGlobalBlock` (blocks από το `__DATA.__const`)
- `NSConcreteMallocBlock` (blocks στο heap)
- `NSConcreateStackBlock` (blocks στο stack)
- Διαθέτει **`flags`** (που υποδεικνύουν τα πεδία τα οποία υπάρχουν στο block descriptor) και ορισμένα reserved bytes
- Ο function pointer που καλείται
- Έναν pointer στο block descriptor
- Block imported variables (εάν υπάρχουν)
- **block descriptor**: Το μέγεθός του εξαρτάται από τα δεδομένα που υπάρχουν (όπως υποδεικνύεται από τα προηγούμενα flags)
- Διαθέτει ορισμένα reserved bytes
- Το μέγεθός του
- Συνήθως διαθέτει έναν pointer σε signature τύπου Objective-C, ώστε να γνωρίζει πόσος χώρος απαιτείται για τα params (flag `BLOCK_HAS_SIGNATURE`)
- Εάν γίνεται αναφορά σε variables, αυτό το block θα διαθέτει επίσης pointers σε έναν copy helper (που αντιγράφει την τιμή στην αρχή) και έναν dispose helper (που την αποδεσμεύει).

### Queues

Μια dispatch queue είναι ένα named object που παρέχει FIFO ordering των blocks προς εκτέλεση.<sup>[[3]](#references)</sup>

Τα blocks τοποθετούνται σε queues για να εκτελεστούν, και αυτές υποστηρίζουν 2 modes: `DISPATCH_QUEUE_SERIAL` και `DISPATCH_QUEUE_CONCURRENT`. Φυσικά, η **serial** queue **δεν θα έχει** προβλήματα race condition, καθώς ένα block δεν θα εκτελεστεί μέχρι να ολοκληρωθεί το προηγούμενο. Όμως **ο άλλος τύπος queue μπορεί να έχει** τέτοια προβλήματα.

Default queues:

- `.main-thread`: Από το `dispatch_get_main_queue()`
- `.libdispatch-manager`: Ο queue manager του GCD
- `.root.libdispatch-manager`: Ο queue manager του GCD
- `.root.maintenance-qos`: Tasks με τη χαμηλότερη προτεραιότητα
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

Σημειώστε ότι το σύστημα αποφασίζει **ποια threads χειρίζονται ποιες queues κάθε χρονική στιγμή** (πολλά threads μπορεί να εργάζονται στην ίδια queue ή το ίδιο thread μπορεί κάποια στιγμή να εργάζεται σε διαφορετικές queues).

#### Attributtes

Κατά τη δημιουργία μιας queue με το **`dispatch_queue_create`**, το τρίτο argument είναι ένα `dispatch_queue_attr_t`, το οποίο συνήθως είναι είτε `DISPATCH_QUEUE_SERIAL` (το οποίο στην πραγματικότητα είναι NULL) είτε `DISPATCH_QUEUE_CONCURRENT`, που είναι ένας pointer σε ένα struct `dispatch_queue_attr_t`, το οποίο επιτρέπει τον έλεγχο ορισμένων παραμέτρων της queue.

### Dispatch objects

Υπάρχουν διάφορα objects που χρησιμοποιεί το libdispatch και οι queues και τα blocks είναι μόνο 2 από αυτά. Είναι δυνατή η δημιουργία αυτών των objects με το `dispatch_object_create`:<sup>[[1]](#references)[[2]](#references)</sup>

- `block`
- `data`: Data blocks
- `group`: Group από blocks
- `io`: Async I/O requests
- `mach`: Mach ports
- `mach_msg`: Mach messages
- `pthread_root_queue`:Μια queue με pthread thread pool και όχι workqueues
- `queue`
- `semaphore`
- `source`: Event source

## Objective-C

Στο Objective-C υπάρχουν διαφορετικές functions για την αποστολή ενός block προς παράλληλη εκτέλεση:

- [**dispatch_async**](https://developer.apple.com/documentation/dispatch/1453057-dispatch_async): Υποβάλλει ένα block για asynchronous εκτέλεση σε μια dispatch queue και επιστρέφει αμέσως.
- [**dispatch_sync**](https://developer.apple.com/documentation/dispatch/1452870-dispatch_sync): Υποβάλλει ένα block object για εκτέλεση και επιστρέφει αφού ολοκληρωθεί η εκτέλεση αυτού του block.
- [**dispatch_once**](https://developer.apple.com/documentation/dispatch/1447169-dispatch_once): Εκτελεί ένα block object μόνο μία φορά κατά τη διάρκεια ζωής μιας εφαρμογής.
- [**dispatch_async_and_wait**](https://developer.apple.com/documentation/dispatch/3191901-dispatch_async_and_wait): Υποβάλλει ένα work item για εκτέλεση και επιστρέφει μόνο αφού ολοκληρωθεί η εκτέλεσή του. Σε αντίθεση με το [**`dispatch_sync`**](https://developer.apple.com/documentation/dispatch/1452870-dispatch_sync), αυτή η function σέβεται όλα τα attributes της queue όταν εκτελεί το block.

Αυτές οι functions αναμένουν τις εξής παραμέτρους: [**`dispatch_queue_t`**](https://developer.apple.com/documentation/dispatch/dispatch_queue_t) **`queue,`** [**`dispatch_block_t`**](https://developer.apple.com/documentation/dispatch/dispatch_block_t) **`block`**

Αυτό είναι το **struct ενός Block**:
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
Και αυτό είναι ένα παράδειγμα χρήσης **parallelism** με το **`dispatch_async`**:
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

**`libswiftDispatch`** είναι μια βιβλιοθήκη που παρέχει **Swift bindings** για το framework Grand Central Dispatch (GCD), το οποίο έχει γραφτεί αρχικά σε C.\
Η βιβλιοθήκη **`libswiftDispatch`** περιτυλίγει τα C GCD APIs σε ένα πιο φιλικό προς τη Swift interface, διευκολύνοντας τους Swift developers να εργάζονται με το GCD με πιο εύκολο και διαισθητικό τρόπο.

- **`DispatchQueue.global().sync{ ... }`**
- **`DispatchQueue.global().async{ ... }`**
- **`let onceToken = DispatchOnce(); onceToken.perform { ... }`**
- **`async await`**
- **`var (data, response) = await URLSession.shared.data(from: URL(string: "https://api.example.com/getData"))`**

**Παράδειγμα κώδικα**:
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

Το ακόλουθο Frida script μπορεί να χρησιμοποιηθεί για να κάνει **hook σε διάφορες συναρτήσεις `dispatch`** και να εξάγει το όνομα της queue, το backtrace και το block: [**https://github.com/seemoo-lab/frida-scripts/blob/main/scripts/libdispatch.js**](https://github.com/seemoo-lab/frida-scripts/blob/main/scripts/libdispatch.js).
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

Επί του παρόντος, το Ghidra δεν κατανοεί ούτε τη δομή ObjectiveC **`dispatch_block_t`**, ούτε τη δομή **`swift_dispatch_block`**.

Επομένως, αν θέλετε να τις κατανοεί, μπορείτε απλώς να τις **δηλώσετε**:

<figure><img src="../../images/image (1160).png" alt="" width="563"><figcaption></figcaption></figure>

<figure><img src="../../images/image (1162).png" alt="" width="563"><figcaption></figcaption></figure>

<figure><img src="../../images/image (1163).png" alt="" width="563"><figcaption></figcaption></figure>

Στη συνέχεια, βρείτε ένα σημείο στον κώδικα όπου **χρησιμοποιούνται**:

> [!TIP]
> Σημειώστε όλες τις αναφορές που γίνονται στο "block", ώστε να κατανοήσετε πώς μπορείτε να συμπεράνετε ότι χρησιμοποιείται η δομή.

<figure><img src="../../images/image (1164).png" alt="" width="563"><figcaption></figcaption></figure>

Κάντε δεξί κλικ στη μεταβλητή -> Retype Variable και επιλέξτε σε αυτήν την περίπτωση **`swift_dispatch_block`**:

<figure><img src="../../images/image (1165).png" alt="" width="563"><figcaption></figcaption></figure>

Το Ghidra θα επανεγγράψει αυτόματα τα πάντα:

<figure><img src="../../images/image (1166).png" alt="" width="563"><figcaption></figcaption></figure>

## References

- [1] [libdispatch — `src/queue.c` (υλοποίηση queue/thread-pool)](https://github.com/apple-oss-distributions/libdispatch/blob/main/src/queue.c)
- [2] [libdispatch — `src/source.c` (dispatch sources)](https://github.com/apple-oss-distributions/libdispatch/blob/main/src/source.c)
- [3] [libdispatch — `dispatch/queue.h` (public queue API)](https://github.com/apple-oss-distributions/libdispatch/blob/main/dispatch/queue.h)
- [4] [Apple Developer — Dispatch](https://developer.apple.com/documentation/dispatch)

{{#include ../../banners/hacktricks-training.md}}
