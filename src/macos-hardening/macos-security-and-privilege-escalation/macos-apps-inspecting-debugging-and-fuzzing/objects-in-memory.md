# Objects in memory

{{#include ../../../banners/hacktricks-training.md}}

## CFRuntimeClass

Vitu vya CF* vinatoka CoreFoundation, ambayo hutoa zaidi ya madarasa 50 ya vitu kama `CFString`, `CFNumber` au `CFAllocator`.

Madarasa haya yote ni mifano ya darasa `CFRuntimeClass`, ambalo linapoitwa linarudisha index kwa `__CFRuntimeClassTable`. CFRuntimeClass imefafanuliwa katika [**CFRuntime.h**](https://opensource.apple.com/source/CF/CF-1153.18/CFRuntime.h.auto.html):
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

### Sehemu za kumbukumbu zinazotumika

Mengi ya data zinazotumika na runtime ya Objective‑C hubadilika wakati wa utekelezaji, kwa hivyo inatumia idadi ya sehemu kutoka kwa familia ya segments ya Mach‑O `__DATA` katika kumbukumbu. Kihistoria hizi zilijumuisha:

- `__objc_msgrefs` (`message_ref_t`): Marejeo ya ujumbe
- `__objc_ivar` (`ivar`): Vigezo vya mfano
- `__objc_data` (`...`): Data zinazoweza kubadilika
- `__objc_classrefs` (`Class`): Marejeo ya Class
- `__objc_superrefs` (`Class`): Marejeo ya superclass
- `__objc_protorefs` (`protocol_t *`): Marejeo ya protocol
- `__objc_selrefs` (`SEL`): Marejeo ya selector
- `__objc_const` (`...`): Data za Class zisomwa-tu na data nyingine (kwa matumaini) thabiti
- `__objc_imageinfo` (`version, flags`): Inatumiwa wakati wa kupakia image: Version kwa sasa `0`; Flags zinaelezea msaada wa GC uliotangulia-kuwekwa, n.k.
- `__objc_protolist` (`protocol_t *`): Orodha ya protocol
- `__objc_nlcatlist` (`category_t`): Kiashirio kwa Non-Lazy Categories zilizofafanuliwa katika binary hii
- `__objc_catlist` (`category_t`): Kiashirio kwa Categories zilizofafanuliwa katika binary hii
- `__objc_nlclslist` (`classref_t`): Kiashirio kwa Non-Lazy Objective‑C classes zilizofafanuliwa katika binary hii
- `__objc_classlist` (`classref_t`): Viashiria kwa madarasa yote ya Objective‑C yaliyofafanuliwa katika binary hii

Pia inatumia sehemu chache katika segment ya `__TEXT` kuhifadhi thamani thabiti:

- `__objc_methname` (C‑String): Majina ya mbinu
- `__objc_classname` (C‑String): Majina ya Class
- `__objc_methtype` (C‑String): Aina za mbinu

macOS/iOS za kisasa (hasa kwenye Apple Silicon) pia huweka metadata ya Objective‑C/Swift katika:

- `__DATA_CONST`: immutable Objective‑C metadata that can be shared read‑only across processes (for example many `__objc_*` lists now live here).
- `__AUTH` / `__AUTH_CONST`: segments containing pointers that must be authenticated at load or use‑time on arm64e (Pointer Authentication). You will also see `__auth_got` in `__AUTH_CONST` instead of the legacy `__la_symbol_ptr`/`__got` only. When instrumenting or hooking, remember to account for both `__got` and `__auth_got` entries in modern binaries.

Kwa background juu ya dyld pre‑optimization (mf. selector uniquing na class/protocol precomputation) na kwa nini sehemu nyingi zilizo "already fixed up" zinapotoka kwenye shared cache, angalia vyanzo vya Apple `objc-opt` na maelezo ya dyld shared cache. Hii inaathiri wapi na jinsi unavyoweza ku-patch metadata wakati wa runtime.

{{#ref}}
../macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.md
{{#endref}}

### Usimbaji wa Aina

Objective‑C hutumia mangling kuandika kwa usimbaji aina za selector na vigezo vya aina rahisi na tata:

- Aina za msingi hutumia herufi yao ya kwanza ya aina: `i` kwa `int`, `c` kwa `char`, `l` kwa `long`... na hutumia herufi kubwa ikiwa ni unsigned (`L` kwa `unsigned long`).
- Aina nyingine za data hutumia herufi au alama nyingine kama `q` kwa `long long`, `b` kwa bitfields, `B` kwa booleans, `#` kwa classes, `@` kwa `id`, `*` kwa `char *`, `^` kwa generic pointers na `?` kwa zisizoelezewa.
- Arrays, structures and unions hutumia `[`, `{` na `(` mtawalia.

#### Mfano wa Tamko la Mbinu
```objectivec
- (NSString *)processString:(id)input withOptions:(char *)options andError:(id)error;
```
Selector itakuwa `processString:withOptions:andError:`

#### Type Encoding

- `id` inawakilishwa kama `@`
- `char *` inawakilishwa kama `*`

Uwakilishi kamili wa type encoding kwa method ni:
```less
@24@0:8@16*20^@24
```
#### Maelezo ya Kina

1. Aina ya Kurudisha (`NSString *`): Imeandikwa kama `@` ikiwa na urefu 24
2. `self` (mfano wa object): Imeandikwa kama `@`, kwenye offset 0
3. `_cmd` (selector): Imeandikwa kama `:`, kwenye offset 8
4. Argumeni ya kwanza (`char * input`): Imeandikwa kama `*`, kwenye offset 16
5. Argumeni ya pili (`NSDictionary * options`): Imeandikwa kama `@`, kwenye offset 20
6. Argumeni ya tatu (`NSError ** error`): Imeandikwa kama `^@`, kwenye offset 24

Kwa kutumia selector + encoding unaweza kujenga tena method.

### Madarasa

Madarasa katika Objective‑C ni C structs zenye properties, method pointers, n.k. Inawezekana kupata struct `objc_class` katika [**source code**](https://opensource.apple.com/source/objc4/objc4-756.2/runtime/objc-runtime-new.h.auto.html):
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
This class uses some bits of the `isa` field to indicate information about the class.

Then, the struct has a pointer to the struct `class_ro_t` stored on disk which contains attributes of the class like its name, base methods, properties and instance variables. During runtime an additional structure `class_rw_t` is used containing pointers which can be altered such as methods, protocols, properties.

{{#ref}}
../macos-basic-objective-c.md
{{#endref}}

---

## Uwawakilishi wa vitu vya kisasa katika kumbukumbu (arm64e, tagged pointers, Swift)

### `isa` isiyo pointer na Pointer Authentication (arm64e)

On Apple Silicon and recent runtimes the Objective‑C `isa` is not always a raw class pointer. On arm64e it is a packed structure that may also carry a Pointer Authentication Code (PAC). Depending on the platform it may include fields like `nonpointer`, `has_assoc`, `weakly_referenced`, `extra_rc`, and the class pointer itself (shifted or signed). This means blindly dereferencing the first 8 bytes of an Objective‑C object will not always yield a valid `Class` pointer.

Vidokezo vya kiutendaji pale unapofanya debugging kwenye arm64e:

- LLDB will usually strip PAC bits for you when printing Objective‑C objects with `po`, but when working with raw pointers you may need to strip authentication manually:

```lldb
(lldb) expr -l objc++ -- #include <ptrauth.h>
(lldb) expr -l objc++ -- void *raw = ptrauth_strip((void*)0x000000016f123abc, ptrauth_key_asda);
(lldb) expr -l objc++ -O -- (Class)object_getClass((id)raw)
```

- Many function/data pointers in Mach‑O will reside in `__AUTH`/`__AUTH_CONST` and require authentication before use. If you are interposing or re‑binding (e.g., fishhook‑style), ensure you also handle `__auth_got` in addition to legacy `__got`.

Kwa ufafanuzi wa kina kuhusu udhamini za lugha/ABI na intrinsics za `<ptrauth.h>` zinazopatikana kutoka Clang/LLVM, angalia rejea mwishoni mwa ukurasa huu.

### Tagged pointer objects

Some Foundation classes avoid heap allocation by encoding the object’s payload directly in the pointer value (tagged pointers). Detection differs by platform (e.g., the most‑significant bit on arm64, least‑significant on x86_64 macOS). Tagged objects don’t have a regular `isa` stored in memory; the runtime resolves the class from the tag bits. When inspecting arbitrary `id` values:

- Use runtime APIs instead of poking the `isa` field: `object_getClass(obj)` / `[obj class]`.
- In LLDB, just `po (id)0xADDR` will print tagged pointer instances correctly because the runtime is consulted to resolve the class.

### Swift heap objects and metadata

Pure Swift classes are also objects with a header pointing to Swift metadata (not Objective‑C `isa`). To introspect live Swift processes without modifying them you can use the Swift toolchain’s `swift-inspect`, which leverages the Remote Mirror library to read runtime metadata:
```bash
# Xcode toolchain (or Swift.org toolchain) provides swift-inspect
swift-inspect dump-raw-metadata <pid-or-name>
swift-inspect dump-arrays <pid-or-name>
# On Darwin additionally:
swift-inspect dump-concurrency <pid-or-name>
```
Hii ni muhimu sana kwa kuchora ramani ya Swift heap objects na protocol conformances wakati wa reversing ya apps mchanganyiko za Swift/ObjC.

---

## Muhtasari wa uchunguzi wa runtime (LLDB / Frida)

### LLDB

- Chapisha object au class kutoka kwa raw pointer:
```lldb
(lldb) expr -l objc++ -O -- (id)0x0000000101234560
(lldb) expr -l objc++ -O -- (Class)object_getClass((id)0x0000000101234560)
```
- Chunguza Objective‑C class kutoka kwa pointer wa `self` wa methodi ya object kwenye breakpoint:
```lldb
(lldb) br se -n '-[NSFileManager fileExistsAtPath:]'
(lldb) r
... breakpoint hit ...
(lldb) po (id)$x0                 # self
(lldb) expr -l objc++ -O -- (Class)object_getClass((id)$x0)
```
- Dump sehemu zinazobeba metadata ya Objective‑C (kumbuka: nyingi sasa ziko katika `__DATA_CONST` / `__AUTH_CONST`):
```lldb
(lldb) image dump section --section __DATA_CONST.__objc_classlist
(lldb) image dump section --section __DATA_CONST.__objc_selrefs
(lldb) image dump section --section __AUTH_CONST.__auth_got
```
- Soma kumbukumbu za object ya darasa inayojulikana ili kuhamia kwa `class_ro_t` / `class_rw_t` wakati unarudisha nyuma orodha za method:
```lldb
(lldb) image lookup -r -n _OBJC_CLASS_$_NSFileManager
(lldb) memory read -fx -s8 0xADDRESS_OF_CLASS_OBJECT
```
### Frida (Objective‑C and Swift)

Frida inatoa madaraja ya juu ya runtime ambayo ni ya manufaa sana kugundua na kuingilia vitu vinavyoendesha bila symbols:

- Orodhesha madarasa na mbinu, tatua majina halisi ya madarasa wakati wa runtime, na kunasa Objective‑C selectors:
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
- Swift bridge: orodhesha aina za Swift na kuingiliana na instances za Swift (inahitaji Frida ya hivi karibuni; inafaa sana kwenye Apple Silicon targets).

---

## Marejeo

- Clang/LLVM: Pointer Authentication na the `<ptrauth.h>` intrinsics (arm64e ABI). https://clang.llvm.org/docs/PointerAuthentication.html
- Apple objc runtime headers (tagged pointers, non‑pointer `isa`, etc.) e.g., `objc-object.h`. https://opensource.apple.com/source/objc4/objc4-818.2/runtime/objc-object.h.auto.html

{{#include ../../../banners/hacktricks-training.md}}
