# Αντικείμενα στη μνήμη

{{#include ../../../banners/hacktricks-training.md}}

## CFRuntimeClass

Τα αντικείμενα CF* προέρχονται από το CoreFoundation, το οποίο παρέχει περισσότερες από 50 κλάσεις αντικειμένων όπως `CFString`, `CFNumber` ή `CFAllocator`.

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

### Τμήματα μνήμης που χρησιμοποιούνται

Τα περισσότερα δεδομένα που χρησιμοποιεί το Objective‑C runtime αλλάζουν κατά την εκτέλεση, επομένως χρησιμοποιεί έναν αριθμό τμημάτων από την Mach‑O `__DATA` οικογένεια τμημάτων στη μνήμη. Ιστορικά αυτά περιλάμβαναν:

- `__objc_msgrefs` (`message_ref_t`): Αναφορές μηνυμάτων
- `__objc_ivar` (`ivar`): Instance variables
- `__objc_data` (`...`): Mutable data
- `__objc_classrefs` (`Class`): Αναφορές κλάσεων
- `__objc_superrefs` (`Class`): Αναφορές superclass
- `__objc_protorefs` (`protocol_t *`): Αναφορές πρωτοκόλλων
- `__objc_selrefs` (`SEL`): Αναφορές selectors
- `__objc_const` (`...`): r/o δεδομένα κλάσης και άλλα (ελπίζουμε) σταθερά δεδομένα
- `__objc_imageinfo` (`version, flags`): Χρησιμοποιείται κατά το φόρτωμα του image: Η έκδοση αυτή τη στιγμή `0`; Τα flags προσδιορίζουν υποστήριξη προεπεξεργασίας GC, κ.λπ.
- `__objc_protolist` (`protocol_t *`): Λίστα πρωτοκόλλων
- `__objc_nlcatlist` (`category_t`): Δείκτης σε Non‑Lazy Categories ορισμένες σε αυτό το binary
- `__objc_catlist` (`category_t`): Δείκτης σε Categories ορισμένες σε αυτό το binary
- `__objc_nlclslist` (`classref_t`): Δείκτης σε Non‑Lazy Objective‑C classes ορισμένες σε αυτό το binary
- `__objc_classlist` (`classref_t`): Δείκτες σε όλες τις Objective‑C κλάσεις ορισμένες σε αυτό το binary

Χρησιμοποιεί επίσης μερικά τμήματα στο `__TEXT` segment για την αποθήκευση σταθερών:

- `__objc_methname` (C‑String): Ονόματα μεθόδων
- `__objc_classname` (C‑String): Ονόματα κλάσεων
- `__objc_methtype` (C‑String): Τύποι μεθόδων

Σύγχρονα macOS/iOS (ειδικά σε Apple Silicon) τοποθετούν επίσης metadata Objective‑C/Swift σε:

- `__DATA_CONST`: αμετάβλητα Objective‑C metadata που μπορούν να κοινοποιηθούν μόνο για ανάγνωση μεταξύ διεργασιών (για παράδειγμα πολλές λίστες `__objc_*` πλέον ζουν εδώ).
- `__AUTH` / `__AUTH_CONST`: segments που περιέχουν δείκτες που πρέπει να είναι authenticated κατά το φόρτωμα ή την ώρα χρήσης στο arm64e (Pointer Authentication). Θα δείτε επίσης `__auth_got` σε `__AUTH_CONST` αντί του legacy `__la_symbol_ptr`/`__got` μόνο. Όταν κάνετε instrumentation ή hooking, θυμηθείτε να λάβετε υπόψη τόσο τις `__got` όσο και τις `__auth_got` εγγραφές σε σύγχρονα binaries.

Για υπόβαθρο σχετικά με το dyld pre‑optimization (π.χ., selector uniquing και class/protocol precomputation) και γιατί πολλά από αυτά τα τμήματα είναι "ήδη διορθωμένα" όταν προέρχονται από το shared cache, δείτε τις Apple `objc-opt` πηγές και τις σημειώσεις dyld shared cache. Αυτό επηρεάζει πού και πώς μπορείτε να τροποποιήσετε metadata κατά το runtime.

{{#ref}}
../macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.md
{{#endref}}

### Κωδικοποίηση τύπων

Το Objective‑C χρησιμοποιεί mangling για να κωδικοποιήσει selectors και τύπους μεταβλητών απλών και σύνθετων τύπων:

- Οι πρωτόγονοι τύποι χρησιμοποιούν το πρώτο γράμμα του τύπου `i` για `int`, `c` για `char`, `l` για `long`... και χρησιμοποιούν το κεφαλαίο γράμμα στην περίπτωση που είναι χωρίς πρόσημο (`L` για `unsigned long`).
- Άλλοι τύποι δεδομένων χρησιμοποιούν άλλα γράμματα ή σύμβολα όπως `q` για `long long`, `b` για bitfields, `B` για λογικές τιμές (booleans), `#` για classes, `@` για `id`, `*` για `char *`, `^` για γενικούς δείκτες και `?` για undefined.
- Πίνακες, δομές και unions χρησιμοποιούν αντίστοιχα τα `[`, `{` και `(`.

#### Παράδειγμα δήλωσης μεθόδου
```objectivec
- (NSString *)processString:(id)input withOptions:(char *)options andError:(id)error;
```
Ο selector θα είναι `processString:withOptions:andError:`

#### Κωδικοποίηση Τύπου

- `id` κωδικοποιείται ως `@`
- `char *` κωδικοποιείται ως `*`

Η πλήρης κωδικοποίηση τύπου για τη μέθοδο είναι:
```less
@24@0:8@16*20^@24
```
#### Λεπτομερής Ανάλυση

1. Τύπος επιστροφής (`NSString *`): Κωδικοποιείται ως `@` με μήκος 24
2. `self` (παράδειγμα αντικειμένου): Κωδικοποιείται ως `@`, στη μετατόπιση 0
3. `_cmd` (επιλογέας): Κωδικοποιείται ως `:`, στη μετατόπιση 8
4. Πρώτο όρισμα (`char * input`): Κωδικοποιείται ως `*`, στη μετατόπιση 16
5. Δεύτερο όρισμα (`NSDictionary * options`): Κωδικοποιείται ως `@`, στη μετατόπιση 20
6. Τρίτο όρισμα (`NSError ** error`): Κωδικοποιείται ως `^@`, στη μετατόπιση 24

Με τον επιλογέα + την κωδικοποίηση μπορείτε να ανακατασκευάσετε τη μέθοδο.

### Κλάσεις

Οι κλάσεις στο Objective‑C είναι C structs με ιδιότητες, δείκτες μεθόδων, κ.λπ. Είναι δυνατόν να βρείτε τη δομή `objc_class` στο [**source code**](https://opensource.apple.com/source/objc4/objc4-756.2/runtime/objc-runtime-new.h.auto.html):
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
Αυτή η κλάση χρησιμοποιεί κάποια bits του πεδίου `isa` για να υποδείξει πληροφορίες σχετικά με την κλάση.

Στη συνέχεια, η struct έχει έναν δείκτη στη struct `class_ro_t` αποθηκευμένη στον δίσκο που περιέχει χαρακτηριστικά της κλάσης όπως το όνομά της, τις base methods, properties και instance variables. Κατά το runtime χρησιμοποιείται μια επιπλέον δομή `class_rw_t` που περιέχει δείκτες οι οποίοι μπορούν να τροποποιηθούν, όπως methods, protocols, properties.

{{#ref}}
../macos-basic-objective-c.md
{{#endref}}

---

## Σύγχρονες αναπαραστάσεις αντικειμένων στη μνήμη (arm64e, tagged pointers, Swift)

### Μη‑δείκτης `isa` και Pointer Authentication (arm64e)

Σε Apple Silicon και σε πρόσφατα runtimes, το Objective‑C `isa` δεν είναι πάντα ένας raw class pointer. Στο arm64e είναι μια πακεταρισμένη δομή που μπορεί επίσης να φέρει ένα Pointer Authentication Code (PAC). Ανάλογα με την πλατφόρμα μπορεί να περιλαμβάνει πεδία όπως `nonpointer`, `has_assoc`, `weakly_referenced`, `extra_rc`, και τον ίδιο τον δείκτη κλάσης (με shifted ή signed μορφή). Αυτό σημαίνει ότι η τυφλή αποαναφορά των πρώτων 8 bytes ενός Objective‑C αντικειμένου δεν θα επιστρέψει πάντα έναν έγκυρο δείκτη `Class`.

Πρακτικές σημειώσεις κατά το debugging σε arm64e:

- Το LLDB συνήθως θα αφαιρεί τα PAC bits για εσάς όταν εκτυπώνει Objective‑C αντικείμενα με `po`, αλλά όταν εργάζεστε με raw pointers ίσως χρειαστεί να αφαιρέσετε την authentication χειροκίνητα:

```lldb
(lldb) expr -l objc++ -- #include <ptrauth.h>
(lldb) expr -l objc++ -- void *raw = ptrauth_strip((void*)0x000000016f123abc, ptrauth_key_asda);
(lldb) expr -l objc++ -O -- (Class)object_getClass((id)raw)
```

- Πολλοί function/data pointers στο Mach‑O θα βρίσκονται σε `__AUTH`/`__AUTH_CONST` και απαιτούν authentication πριν τη χρήση. Αν κάνετε interposing ή re‑binding (π.χ. fishhook‑style), βεβαιωθείτε ότι χειρίζεστε επίσης το `__auth_got` επιπλέον του legacy `__got`.

Για εις βάθος ανάλυση σχετικά με τις εγγυήσεις γλώσσας/ABI και τα intrinsics του `<ptrauth.h>` που είναι διαθέσιμα από το Clang/LLVM, δείτε την αναφορά στο τέλος αυτής της σελίδας.

### Tagged pointer objects

Ορισμένες Foundation κλάσεις αποφεύγουν την κατανομή στο heap κωδικοποιώντας το payload του αντικειμένου απευθείας στην τιμή του pointer (tagged pointers). Ο εντοπισμός διαφέρει ανά πλατφόρμα (π.χ. το most‑significant bit στο arm64, το least‑significant στο x86_64 macOS). Τα tagged αντικείμενα δεν έχουν ένα κανονικό `isa` αποθηκευμένο στη μνήμη· το runtime επιλύει την κλάση από τα tag bits. Όταν εξετάζετε αυθαίρετες τιμές `id`:

- Χρησιμοποιήστε runtime APIs αντί να πειράζετε το πεδίο `isa`: `object_getClass(obj)` / `[obj class]`.
- Στο LLDB, απλώς `po (id)0xADDR` θα εκτυπώσει σωστά αντικείμενα tagged pointer επειδή το runtime συμβουλεύεται για να επιλύσει την κλάση.

### Swift heap objects and metadata

Οι καθαρές Swift κλάσεις είναι επίσης αντικείμενα με ένα header που δείχνει σε Swift metadata (όχι Objective‑C `isa`). Για να κάνετε introspect ζωντανών Swift διεργασιών χωρίς να τις τροποποιήσετε μπορείτε να χρησιμοποιήσετε το Swift toolchain’s `swift-inspect`, που αξιοποιεί τη βιβλιοθήκη Remote Mirror για να διαβάσει runtime metadata:
```bash
# Xcode toolchain (or Swift.org toolchain) provides swift-inspect
swift-inspect dump-raw-metadata <pid-or-name>
swift-inspect dump-arrays <pid-or-name>
# On Darwin additionally:
swift-inspect dump-concurrency <pid-or-name>
```
Αυτό είναι πολύ χρήσιμο για να αντιστοιχίσετε αντικείμενα heap του Swift και τις συμμορφώσεις πρωτοκόλλων όταν κάνετε reversing σε μικτές εφαρμογές Swift/ObjC.

---

## Cheatsheet επιθεώρησης χρόνου εκτέλεσης (LLDB / Frida)

### LLDB

- Εκτύπωση αντικειμένου ή κλάσης από raw pointer:
```lldb
(lldb) expr -l objc++ -O -- (id)0x0000000101234560
(lldb) expr -l objc++ -O -- (Class)object_getClass((id)0x0000000101234560)
```
- Επισκόπηση της κλάσης Objective‑C από ένα pointer προς το `self` μιας μεθόδου αντικειμένου σε breakpoint:
```lldb
(lldb) br se -n '-[NSFileManager fileExistsAtPath:]'
(lldb) r
... breakpoint hit ...
(lldb) po (id)$x0                 # self
(lldb) expr -l objc++ -O -- (Class)object_getClass((id)$x0)
```
- Εξάγετε ενότητες που περιέχουν μεταδεδομένα Objective‑C (σημείωση: πολλές πλέον βρίσκονται σε `__DATA_CONST` / `__AUTH_CONST`):
```lldb
(lldb) image dump section --section __DATA_CONST.__objc_classlist
(lldb) image dump section --section __DATA_CONST.__objc_selrefs
(lldb) image dump section --section __AUTH_CONST.__auth_got
```
- Διάβασε τη μνήμη ενός γνωστού αντικειμένου κλάσης για να pivot σε `class_ro_t` / `class_rw_t` όταν κάνεις reversing στις λίστες μεθόδων:
```lldb
(lldb) image lookup -r -n _OBJC_CLASS_$_NSFileManager
(lldb) memory read -fx -s8 0xADDRESS_OF_CLASS_OBJECT
```
### Frida (Objective‑C and Swift)

Η Frida παρέχει υψηλού επιπέδου runtime γέφυρες που είναι πολύ χρήσιμες για να εντοπίζετε και να επεμβαίνετε σε ζωντανά αντικείμενα χωρίς σύμβολα:

- Επισκόπηση των classes και methods, επίλυση των πραγματικών ονομάτων κλάσεων κατά το runtime, και παρεμβολή σε Objective‑C selectors:
```js
if (ObjC.available) {
// List a class' methods
console.log(ObjC.classes.NSFileManager.$ownMethods);

// Intercept and inspect arguments/return values
const impl = ObjC.classes.NSFileManager['- fileExistsAtPath:isDirectory:'].implementation;
Interceptor.attach(impl, {
onEnter(args) {
this.path = new ObjC.Object(args[2]).toString();
},
onLeave(retval) {
console.log('fileExistsAtPath:', this.path, '=>', retval);
}
});
}
```
- Swift bridge: απαριθμήστε Swift types και αλληλεπιδράστε με Swift instances (απαιτεί πρόσφατο Frida· πολύ χρήσιμο σε συσκευές Apple Silicon).

---

## Αναφορές

- Clang/LLVM: Pointer Authentication and the `<ptrauth.h>` intrinsics (arm64e ABI). https://clang.llvm.org/docs/PointerAuthentication.html
- Apple objc runtime headers (tagged pointers, non‑pointer `isa`, etc.) π.χ. `objc-object.h`. https://opensource.apple.com/source/objc4/objc4-818.2/runtime/objc-object.h.auto.html

{{#include ../../../banners/hacktricks-training.md}}
