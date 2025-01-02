# Αντικείμενα στη μνήμη

{{#include ../../../banners/hacktricks-training.md}}

## CFRuntimeClass

CF\* αντικείμενα προέρχονται από το CoreFoundation, το οποίο παρέχει περισσότερες από 50 κλάσεις αντικειμένων όπως `CFString`, `CFNumber` ή `CFAllocator`.

Όλες αυτές οι κλάσεις είναι στιγμιότυπα της κλάσης `CFRuntimeClass`, η οποία όταν καλείται επιστρέφει έναν δείκτη στον `__CFRuntimeClassTable`. Η CFRuntimeClass ορίζεται στο [**CFRuntime.h**](https://opensource.apple.com/source/CF/CF-1153.18/CFRuntime.h.auto.html):
```objectivec
// Some comments were added to the original code

enum { // Version field constants
_kCFRuntimeScannedObject =     (1UL << 0),
_kCFRuntimeResourcefulObject = (1UL << 2),  // tells CFRuntime to make use of the reclaim field
_kCFRuntimeCustomRefCount =    (1UL << 3),  // tells CFRuntime to make use of the refcount field
_kCFRuntimeRequiresAlignment = (1UL << 4),  // tells CFRuntime to make use of the requiredAlignment field
};

typedef struct __CFRuntimeClass {
CFIndex version;  // This is made a bitwise OR with the relevant previous flags

const char *className; // must be a pure ASCII string, nul-terminated
void (*init)(CFTypeRef cf);  // Initializer function
CFTypeRef (*copy)(CFAllocatorRef allocator, CFTypeRef cf); // Copy function, taking CFAllocatorRef and CFTypeRef to copy
void (*finalize)(CFTypeRef cf); // Finalizer function
Boolean (*equal)(CFTypeRef cf1, CFTypeRef cf2); // Function to be called by CFEqual()
CFHashCode (*hash)(CFTypeRef cf); // Function to be called by CFHash()
CFStringRef (*copyFormattingDesc)(CFTypeRef cf, CFDictionaryRef formatOptions); // Provides a CFStringRef with a textual description of the object// return str with retain
CFStringRef (*copyDebugDesc)(CFTypeRef cf);	// CFStringRed with textual description of the object for CFCopyDescription

#define CF_RECLAIM_AVAILABLE 1
void (*reclaim)(CFTypeRef cf); // Or in _kCFRuntimeResourcefulObject in the .version to indicate this field should be used
// It not null, it's called when the last reference to the object is released

#define CF_REFCOUNT_AVAILABLE 1
// If not null, the following is called when incrementing or decrementing reference count
uint32_t (*refcount)(intptr_t op, CFTypeRef cf); // Or in _kCFRuntimeCustomRefCount in the .version to indicate this field should be used
// this field must be non-NULL when _kCFRuntimeCustomRefCount is in the .version field
// - if the callback is passed 1 in 'op' it should increment the 'cf's reference count and return 0
// - if the callback is passed 0 in 'op' it should return the 'cf's reference count, up to 32 bits
// - if the callback is passed -1 in 'op' it should decrement the 'cf's reference count; if it is now zero, 'cf' should be cleaned up and deallocated (the finalize callback above will NOT be called unless the process is running under GC, and CF does not deallocate the memory for you; if running under GC, finalize should do the object tear-down and free the object memory); then return 0
// remember to use saturation arithmetic logic and stop incrementing and decrementing when the ref count hits UINT32_MAX, or you will have a security bug
// remember that reference count incrementing/decrementing must be done thread-safely/atomically
// objects should be created/initialized with a custom ref-count of 1 by the class creation functions
// do not attempt to use any bits within the CFRuntimeBase for your reference count; store that in some additional field in your CF object

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wmissing-field-initializers"
#define CF_REQUIRED_ALIGNMENT_AVAILABLE 1
// If not 0, allocation of object must be on this boundary
uintptr_t requiredAlignment; // Or in _kCFRuntimeRequiresAlignment in the .version field to indicate this field should be used; the allocator to _CFRuntimeCreateInstance() will be ignored in this case; if this is less than the minimum alignment the system supports, you'll get higher alignment; if this is not an alignment the system supports (e.g., most systems will only support powers of two, or if it is too high), the result (consequences) will be up to CF or the system to decide

} CFRuntimeClass;
```
## Objective-C

### Memory sections used

Οι περισσότερες από τις δεδομένες πληροφορίες που χρησιμοποιούνται από το ObjectiveC runtime θα αλλάξουν κατά τη διάρκεια της εκτέλεσης, επομένως χρησιμοποιεί ορισμένες ενότητες από το **\_\_DATA** τμήμα στη μνήμη:

- **`__objc_msgrefs`** (`message_ref_t`): Αναφορές μηνυμάτων
- **`__objc_ivar`** (`ivar`): Μεταβλητές στιγμής
- **`__objc_data`** (`...`): Μεταβλητά δεδομένα
- **`__objc_classrefs`** (`Class`): Αναφορές κλάσεων
- **`__objc_superrefs`** (`Class`): Αναφορές υπερκλάσεων
- **`__objc_protorefs`** (`protocol_t *`): Αναφορές πρωτοκόλλων
- **`__objc_selrefs`** (`SEL`): Αναφορές επιλεγέων
- **`__objc_const`** (`...`): Δεδομένα κλάσης `r/o` και άλλα (ελπίζουμε) σταθερά δεδομένα
- **`__objc_imageinfo`** (`version, flags`): Χρησιμοποιείται κατά τη φόρτωση εικόνας: Έκδοση αυτή τη στιγμή `0`; Οι σημαίες καθορίζουν την υποστήριξη προ-βελτιστοποιημένου GC, κ.λπ.
- **`__objc_protolist`** (`protocol_t *`): Λίστα πρωτοκόλλων
- **`__objc_nlcatlist`** (`category_t`): Δείκτης σε Μη-Τεμπέλικες Κατηγορίες που ορίζονται σε αυτό το δυαδικό
- **`__objc_catlist`** (`category_t`): Δείκτης σε Κατηγορίες που ορίζονται σε αυτό το δυαδικό
- **`__objc_nlclslist`** (`classref_t`): Δείκτης σε Μη-Τεμπέλικες κλάσεις Objective-C που ορίζονται σε αυτό το δυαδικό
- **`__objc_classlist`** (`classref_t`): Δείκτες σε όλες τις κλάσεις Objective-C που ορίζονται σε αυτό το δυαδικό

Χρησιμοποιεί επίσης μερικές ενότητες στο **`__TEXT`** τμήμα για να αποθηκεύσει σταθερές τιμές αν δεν είναι δυνατή η εγγραφή σε αυτή την ενότητα:

- **`__objc_methname`** (C-String): Ονόματα μεθόδων
- **`__objc_classname`** (C-String): Ονόματα κλάσεων
- **`__objc_methtype`** (C-String): Τύποι μεθόδων

### Type Encoding

Το Objective-C χρησιμοποιεί κάποια παραμόρφωση για να κωδικοποιήσει τους επιλεγείς και τους τύπους μεταβλητών απλών και σύνθετων τύπων:

- Οι πρωτότυποι τύποι χρησιμοποιούν το πρώτο γράμμα του τύπου `i` για `int`, `c` για `char`, `l` για `long`... και χρησιμοποιούν το κεφαλαίο γράμμα σε περίπτωση που είναι unsigned (`L` για `unsigned Long`).
- Άλλοι τύποι δεδομένων των οποίων τα γράμματα χρησιμοποιούνται ή είναι ειδικά, χρησιμοποιούν άλλα γράμματα ή σύμβολα όπως `q` για `long long`, `b` για `bitfields`, `B` για `booleans`, `#` για `classes`, `@` για `id`, `*` για `char pointers`, `^` για γενικούς `pointers` και `?` για `undefined`.
- Οι πίνακες, οι δομές και οι ενώσεις χρησιμοποιούν `[`, `{` και `(`

#### Example Method Declaration
```objectivec
- (NSString *)processString:(id)input withOptions:(char *)options andError:(id)error;
```
Ο επιλεγέας θα είναι `processString:withOptions:andError:`

#### Κωδικοποίηση Τύπου

- `id` κωδικοποιείται ως `@`
- `char *` κωδικοποιείται ως `*`

Η πλήρης κωδικοποίηση τύπου για τη μέθοδο είναι:
```less
@24@0:8@16*20^@24
```
#### Λεπτομερής Ανάλυση

1. **Τύπος Επιστροφής (`NSString *`)**: Κωδικοποιημένος ως `@` με μήκος 24
2. **`self` (αντικείμενο στιγμιότυπο)**: Κωδικοποιημένος ως `@`, στη μετατόπιση 0
3. **`_cmd` (επιλογέας)**: Κωδικοποιημένος ως `:`, στη μετατόπιση 8
4. **Πρώτη παράμετρος (`char * input`)**: Κωδικοποιημένος ως `*`, στη μετατόπιση 16
5. **Δεύτερη παράμετρος (`NSDictionary * options`)**: Κωδικοποιημένος ως `@`, στη μετατόπιση 20
6. **Τρίτη παράμετρος (`NSError ** error`)**: Κωδικοποιημένος ως `^@`, στη μετατόπιση 24

**Με τον επιλογέα + την κωδικοποίηση μπορείτε να ανακατασκευάσετε τη μέθοδο.**

### **Κλάσεις**

Οι κλάσεις στην Objective-C είναι μια δομή με ιδιότητες, δείκτες μεθόδων... Είναι δυνατή η εύρεση της δομής `objc_class` στον [**πηγαίο κώδικα**](https://opensource.apple.com/source/objc4/objc4-756.2/runtime/objc-runtime-new.h.auto.html):
```objectivec
struct objc_class : objc_object {
// Class ISA;
Class superclass;
cache_t cache;             // formerly cache pointer and vtable
class_data_bits_t bits;    // class_rw_t * plus custom rr/alloc flags

class_rw_t *data() {
return bits.data();
}
void setData(class_rw_t *newData) {
bits.setData(newData);
}

void setInfo(uint32_t set) {
assert(isFuture()  ||  isRealized());
data()->setFlags(set);
}
[...]
```
Αυτή η κλάση χρησιμοποιεί μερικά bits του πεδίου isa για να υποδείξει κάποιες πληροφορίες σχετικά με την κλάση.

Στη συνέχεια, η δομή έχει έναν δείκτη στη δομή `class_ro_t` που αποθηκεύεται στο δίσκο και περιέχει χαρακτηριστικά της κλάσης όπως το όνομά της, τις βασικές μεθόδους, τις ιδιότητες και τις μεταβλητές στιγμής.\
Κατά τη διάρκεια της εκτέλεσης, χρησιμοποιείται μια επιπλέον δομή `class_rw_t` που περιέχει δείκτες που μπορούν να τροποποιηθούν, όπως μεθόδους, πρωτόκολλα, ιδιότητες...

{{#include ../../../banners/hacktricks-training.md}}
