# Objects in memory

{{#include ../../../banners/hacktricks-training.md}}

## CFRuntimeClass

Τα αντικείμενα CF* προέρχονται από το CoreFoundation, το οποίο παρέχει περισσότερες από 50 κλάσεις αντικειμένων, όπως `CFString`, `CFNumber` ή `CFAllocator`.

Όλες αυτές οι κλάσεις είναι instances της κλάσης `CFRuntimeClass`, η οποία, όταν καλείται, επιστρέφει ένα index στον `__CFRuntimeClassTable`. Το CFRuntimeClass ορίζεται στο [**CFRuntime.h**](https://opensource.apple.com/source/CF/CF-1153.18/CFRuntime.h.auto.html):
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

### Ενότητες μνήμης που χρησιμοποιούνται

Τα περισσότερα δεδομένα που χρησιμοποιούνται από το Objective‑C runtime αλλάζουν κατά την εκτέλεση, επομένως χρησιμοποιούνται αρκετές ενότητες από την οικογένεια segments `__DATA` του Mach‑O στη μνήμη. Ιστορικά, αυτές περιλάμβαναν:

- `__objc_msgrefs` (`message_ref_t`): Αναφορές σε messages
- `__objc_ivar` (`ivar`): Instance variables
- `__objc_data` (`...`): Mutable δεδομένα
- `__objc_classrefs` (`Class`): Αναφορές σε classes
- `__objc_superrefs` (`Class`): Αναφορές σε superclasses
- `__objc_protorefs` (`protocol_t *`): Αναφορές σε protocols
- `__objc_selrefs` (`SEL`): Αναφορές σε selectors
- `__objc_const` (`...`): Class r/o δεδομένα και άλλα (ελπίζουμε) constant δεδομένα
- `__objc_imageinfo` (`version, flags`): Χρησιμοποιείται κατά το image load: Η τρέχουσα έκδοση είναι `0`. Τα flags καθορίζουν υποστήριξη preoptimized GC κ.λπ.
- `__objc_protolist` (`protocol_t *`): Λίστα protocols
- `__objc_nlcatlist` (`category_t`): Pointer προς Non-Lazy Categories που ορίζονται σε αυτό το binary
- `__objc_catlist` (`category_t`): Pointer προς Categories που ορίζονται σε αυτό το binary
- `__objc_nlclslist` (`classref_t`): Pointer προς Non-Lazy Objective‑C classes που ορίζονται σε αυτό το binary
- `__objc_classlist` (`classref_t`): Pointers προς όλες τις Objective‑C classes που ορίζονται σε αυτό το binary

Χρησιμοποιεί επίσης μερικές ενότητες στο segment `__TEXT` για την αποθήκευση constants:

- `__objc_methname` (C‑String): Ονόματα methods
- `__objc_classname` (C‑String): Ονόματα classes
- `__objc_methtype` (C‑String): Τύποι methods

Τα σύγχρονα macOS/iOS (ιδιαίτερα στο Apple Silicon) τοποθετούν επίσης metadata του Objective‑C/Swift στα εξής:

- `__DATA_CONST`: Immutable Objective‑C metadata που μπορούν να γίνουν read-only shared μεταξύ processes (για παράδειγμα, πολλές λίστες `__objc_*` βρίσκονται πλέον εδώ).
- `__AUTH` / `__AUTH_CONST`: Segments που περιέχουν pointers οι οποίοι πρέπει να authenticated κατά το load ή κατά τη χρήση σε arm64e (Pointer Authentication). Θα δείτε επίσης το `__auth_got` στο `__AUTH_CONST` αντί για τα παλαιότερα `__la_symbol_ptr`/`__got` και μόνο. Κατά το instrumenting ή hooking, θυμηθείτε να λαμβάνετε υπόψη entries τόσο του `__got` όσο και του `__auth_got` σε σύγχρονα binaries.

Για background σχετικά με το dyld pre‑optimization (π.χ. selector uniquing και class/protocol precomputation) και για το γιατί πολλές από αυτές τις ενότητες είναι «already fixed up» όταν προέρχονται από το shared cache, ελέγξτε τα sources του Apple `objc-opt` και τις σημειώσεις για το dyld shared cache. Αυτό επηρεάζει το πού και με ποιον τρόπο μπορείτε να κάνετε patch metadata κατά το runtime.

{{#ref}}
../macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.md
{{#endref}}

### Κωδικοποίηση τύπων

Το Objective‑C χρησιμοποιεί mangling για την κωδικοποίηση των τύπων selector και variable, τόσο απλών όσο και σύνθετων:

- Οι primitive τύποι χρησιμοποιούν το πρώτο γράμμα του τύπου: `i` για `int`, `c` για `char`, `l` για `long`... και χρησιμοποιούν το κεφαλαίο γράμμα όταν πρόκειται για unsigned (`L` για `unsigned long`).
- Οι άλλοι τύποι δεδομένων χρησιμοποιούν άλλα γράμματα ή σύμβολα, όπως `q` για `long long`, `b` για bitfields, `B` για booleans, `#` για classes, `@` για `id`, `*` για `char *`, `^` για generic pointers και `?` για undefined.
- Τα arrays, τα structures και τα unions χρησιμοποιούν αντίστοιχα τα `[`, `{` και `(`.

#### Παράδειγμα δήλωσης Method
```objectivec
- (NSString *)processString:(id)input withOptions:(char *)options andError:(id)error;
```
Ο selector θα ήταν `processString:withOptions:andError:`

#### Κωδικοποίηση Τύπων

- Το `id` κωδικοποιείται ως `@`
- Το `char *` κωδικοποιείται ως `*`

Η πλήρης κωδικοποίηση τύπων για τη μέθοδο είναι:
```less
@24@0:8@16*20^@24
```
#### Λεπτομερής Ανάλυση

1. Τύπος επιστροφής (`NSString *`): Κωδικοποιείται ως `@` με μήκος 24
2. `self` (instance του object): Κωδικοποιείται ως `@`, στο offset 0
3. `_cmd` (selector): Κωδικοποιείται ως `:`, στο offset 8
4. Πρώτο όρισμα (`char * input`): Κωδικοποιείται ως `*`, στο offset 16
5. Δεύτερο όρισμα (`NSDictionary * options`): Κωδικοποιείται ως `@`, στο offset 20
6. Τρίτο όρισμα (`NSError ** error`): Κωδικοποιείται ως `^@`, στο offset 24

Με το selector και το encoding μπορείτε να ανακατασκευάσετε το method.

### Classes

Οι Classes στο Objective-C είναι C structs με properties, method pointers κ.λπ. Είναι δυνατό να βρεθεί το struct `objc_class` στον [**πηγαίο κώδικα**](https://opensource.apple.com/source/objc4/objc4-756.2/runtime/objc-runtime-new.h.auto.html):
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
Αυτή η class χρησιμοποιεί ορισμένα bits του πεδίου `isa` για να υποδεικνύει πληροφορίες σχετικά με την class.

Στη συνέχεια, το struct διαθέτει έναν pointer προς το struct `class_ro_t`, αποθηκευμένο στον δίσκο, το οποίο περιέχει attributes της class, όπως το όνομά της, τα base methods, τα properties και τα instance variables. Κατά το runtime χρησιμοποιείται μια επιπλέον δομή, η `class_rw_t`, η οποία περιέχει pointers που μπορούν να τροποποιηθούν, όπως methods, protocols και properties.

{{#ref}}
../macos-basic-objective-c.md
{{#endref}}

---

## Σύγχρονες αναπαραστάσεις objects στη μνήμη (arm64e, tagged pointers, Swift)

### Non‑pointer `isa` και Pointer Authentication (arm64e)

Στο Apple Silicon και στα πρόσφατα runtimes, το Objective‑C `isa` δεν είναι πάντα ένας raw class pointer. Στο arm64e είναι μια packed structure που μπορεί επίσης να περιέχει έναν Pointer Authentication Code (PAC). Ανάλογα με την πλατφόρμα, μπορεί να περιλαμβάνει πεδία όπως `nonpointer`, `has_assoc`, `weakly_referenced`, `extra_rc` και τον ίδιο τον class pointer (με μετατόπιση ή υπογεγραμμένο). Αυτό σημαίνει ότι η τυφλή αποαναφορά των πρώτων 8 bytes ενός Objective‑C object δεν θα επιστρέφει πάντα έναν έγκυρο `Class` pointer.<sup>[2]</sup>

Πρακτικές σημειώσεις κατά το debugging σε arm64e:

- Το LLDB συνήθως αφαιρεί τα PAC bits για εσάς όταν εκτυπώνει Objective‑C objects με `po`, αλλά όταν εργάζεστε με raw pointers μπορεί να χρειαστεί να αφαιρέσετε χειροκίνητα το authentication:

```lldb
(lldb) expr -l objc++ -- #include <ptrauth.h>
(lldb) expr -l objc++ -- void *raw = ptrauth_strip((void*)0x000000016f123abc, ptrauth_key_asda);
(lldb) expr -l objc++ -O -- (Class)object_getClass((id)raw)
```

- Πολλοί function/data pointers στο Mach‑O βρίσκονται στα `__AUTH`/`__AUTH_CONST` και απαιτούν authentication πριν από τη χρήση τους. Αν κάνετε interposing ή re-binding (π.χ. σε στυλ fishhook), βεβαιωθείτε ότι χειρίζεστε επίσης το `__auth_got`, εκτός από το legacy `__got`.

Για μια λεπτομερή ανάλυση των εγγυήσεων της γλώσσας/ABI και των intrinsics του `<ptrauth.h>` που διατίθενται από το Clang/LLVM, δείτε το reference στο τέλος αυτής της σελίδας.<sup>[1]</sup>

### Tagged pointer objects

Ορισμένες Foundation classes αποφεύγουν την allocation στο heap κωδικοποιώντας απευθείας το payload του object στην τιμή του pointer (tagged pointers). Η ανίχνευση διαφέρει ανά πλατφόρμα (π.χ. το most-significant bit στο arm64 και το least-significant bit στο x86_64 macOS). Τα tagged objects δεν διαθέτουν ένα κανονικό `isa` αποθηκευμένο στη μνήμη· το runtime επιλύει την class από τα tag bits.<sup>[2]</sup> Κατά την επιθεώρηση αυθαίρετων τιμών `id`:

- Χρησιμοποιήστε runtime APIs αντί να εξετάζετε απευθείας το πεδίο `isa`: `object_getClass(obj)` / `[obj class]`.
- Στο LLDB, το `po (id)0xADDR` θα εκτυπώσει σωστά τα tagged pointer instances, επειδή γίνεται χρήση του runtime για την επίλυση της class.

### Swift heap objects και metadata

Οι pure Swift classes είναι επίσης objects με header που δείχνει σε Swift metadata (και όχι σε Objective‑C `isa`). Για να κάνετε introspect live Swift processes χωρίς να τα τροποποιείτε, μπορείτε να χρησιμοποιήσετε το `swift-inspect` του Swift toolchain, το οποίο αξιοποιεί τη βιβλιοθήκη Remote Mirror για την ανάγνωση runtime metadata:
```bash
# Xcode toolchain (or Swift.org toolchain) provides swift-inspect
swift-inspect dump-raw-metadata <pid-or-name>
swift-inspect dump-arrays <pid-or-name>
# On Darwin additionally:
swift-inspect dump-concurrency <pid-or-name>
```
Αυτό είναι πολύ χρήσιμο για την αντιστοίχιση Swift heap objects και protocol conformances κατά το reversing εφαρμογών mixed Swift/ObjC.

---

## Cheatsheet επιθεώρησης runtime (LLDB / Frida)

### LLDB

- Εκτύπωση object ή class από raw pointer:
```lldb
(lldb) expr -l objc++ -O -- (id)0x0000000101234560
(lldb) expr -l objc++ -O -- (Class)object_getClass((id)0x0000000101234560)
```
- Επιθεώρηση της κλάσης Objective-C από έναν pointer στο `self` μιας μεθόδου object σε ένα breakpoint:
```lldb
(lldb) br se -n '-[NSFileManager fileExistsAtPath:]'
(lldb) r
... breakpoint hit ...
(lldb) po (id)$x0                 # self
(lldb) expr -l objc++ -O -- (Class)object_getClass((id)$x0)
```
- Κάντε dump στα sections που περιέχουν Objective-C metadata (σημείωση: πολλά βρίσκονται πλέον στα `__DATA_CONST` / `__AUTH_CONST`):
```lldb
(lldb) image dump section --section __DATA_CONST.__objc_classlist
(lldb) image dump section --section __DATA_CONST.__objc_selrefs
(lldb) image dump section --section __AUTH_CONST.__auth_got
```
- Διαβάστε τη μνήμη για ένα γνωστό class object, ώστε να κάνετε pivot στα `class_ro_t` / `class_rw_t` κατά το reverse engineering των method lists:
```lldb
(lldb) image lookup -r -n _OBJC_CLASS_$_NSFileManager
(lldb) memory read -fx -s8 0xADDRESS_OF_CLASS_OBJECT
```
### Frida (Objective‑C και Swift)

Το Frida παρέχει high‑level runtime bridges που είναι ιδιαίτερα χρήσιμα για την ανακάλυψη και το instrumentation live objects χωρίς symbols:

- Enumerate classes και methods, resolve actual class names at runtime και intercept Objective‑C selectors:
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
- Swift bridge: απαρίθμηση Swift types και αλληλεπίδραση με Swift instances (απαιτεί πρόσφατη έκδοση του Frida· πολύ χρήσιμο για Apple Silicon targets).

---

## References

- [1] [Clang/LLVM: Pointer Authentication και τα intrinsics του ptrauth.h (arm64e ABI)](https://clang.llvm.org/docs/PointerAuthentication.html)
- [2] [Apple objc runtime headers - objc-object.h (tagged pointers, non-pointer isa κ.λπ.)](https://opensource.apple.com/source/objc4/objc4-818.2/runtime/objc-object.h.auto.html)

{{#include ../../../banners/hacktricks-training.md}}
