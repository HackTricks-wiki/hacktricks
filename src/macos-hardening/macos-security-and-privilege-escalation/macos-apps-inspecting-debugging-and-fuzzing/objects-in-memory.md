# Objects katika memory

{{#include ../../../banners/hacktricks-training.md}}

## CFRuntimeClass

CF* objects hutoka CoreFoundation, ambayo hutoa zaidi ya classes 50 za objects kama `CFString`, `CFNumber` au `CFAllocator`.

Classes hizi zote ni instances za class `CFRuntimeClass`, ambayo inapoitwa hurudisha index kwenye `__CFRuntimeClassTable`. CFRuntimeClass imefafanuliwa katika [**CFRuntime.h**](https://opensource.apple.com/source/CF/CF-1153.18/CFRuntime.h.auto.html):
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

### Sehemu za memory zinazotumika

Data nyingi inayotumiwa na Objective-C runtime itabadilika wakati wa utekelezaji, kwa hiyo hutumia sections kadhaa kutoka kwenye family ya segments za Mach-O `__DATA` katika memory. Kihistoria, hizi zilijumuisha:

- `__objc_msgrefs` (`message_ref_t`): Marejeleo ya messages
- `__objc_ivar` (`ivar`): Instance variables
- `__objc_data` (`...`): Data inayoweza kubadilishwa
- `__objc_classrefs` (`Class`): Marejeleo ya classes
- `__objc_superrefs` (`Class`): Marejeleo ya superclasses
- `__objc_protorefs` (`protocol_t *`): Marejeleo ya protocols
- `__objc_selrefs` (`SEL`): Marejeleo ya selectors
- `__objc_const` (`...`): Data ya class ya kusomwa pekee na data nyingine (inayotumainiwa kuwa) constant
- `__objc_imageinfo` (`version, flags`): Hutumika wakati wa kupakia image: Version kwa sasa ni `0`; Flags hubainisha support ya preoptimized GC, n.k.
- `__objc_protolist` (`protocol_t *`): Orodha ya protocols
- `__objc_nlcatlist` (`category_t`): Pointer ya Non-Lazy Categories zilizofafanuliwa katika binary hii
- `__objc_catlist` (`category_t`): Pointer ya Categories zilizofafanuliwa katika binary hii
- `__objc_nlclslist` (`classref_t`): Pointer ya Non-Lazy Objective-C classes zilizofafanuliwa katika binary hii
- `__objc_classlist` (`classref_t`): Pointers za Objective-C classes zote zilizofafanuliwa katika binary hii

Pia hutumia sections chache katika segment ya `__TEXT` kuhifadhi constants:

- `__objc_methname` (C‑String): Majina ya methods
- `__objc_classname` (C‑String): Majina ya classes
- `__objc_methtype` (C‑String): Aina za methods

Modern macOS/iOS (hasa kwenye Apple Silicon) pia huweka metadata ya Objective-C/Swift katika:

- `__DATA_CONST`: Metadata ya Objective-C isiyoweza kubadilishwa ambayo inaweza kushirikiwa ikiwa read-only kati ya processes (kwa mfano, lists nyingi za `__objc_*` sasa zinaishi hapa).
- `__AUTH` / `__AUTH_CONST`: Segments zenye pointers ambazo lazima zi-authenticate wakati wa kupakia au kuzitumia kwenye arm64e (Pointer Authentication). Pia utaona `__auth_got` katika `__AUTH_CONST` badala ya `__la_symbol_ptr`/`__got` za legacy pekee. Unapofanya instrumentation au hooking, kumbuka kuzingatia entries za `__got` na `__auth_got` katika binaries za kisasa.

Kwa maelezo ya msingi kuhusu dyld pre-optimization (kwa mfano, selector uniquing na precomputation ya classes/protocols) na kwa nini sections nyingi hizi huwa "tayari zimefanyiwa fix up" zinapotoka kwenye shared cache, angalia sources za Apple `objc-opt` na notes za dyld shared cache. Hii huathiri mahali na jinsi unavyoweza kupatch metadata wakati wa runtime.

{{#ref}}
../macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.md
{{#endref}}

### Type Encoding

Objective-C hutumia mangling ku-encode aina za selectors na variables za aina rahisi na changamano:

- Aina primitive hutumia herufi yao ya kwanza, `i` kwa `int`, `c` kwa `char`, `l` kwa `long`... na hutumia herufi kubwa ikiwa ni unsigned (`L` kwa `unsigned long`).
- Aina nyingine za data hutumia herufi au symbols nyingine kama `q` kwa `long long`, `b` kwa bitfields, `B` kwa booleans, `#` kwa classes, `@` kwa `id`, `*` kwa `char *`, `^` kwa generic pointers na `?` kwa undefined.
- Arrays, structures na unions hutumia `[`, `{` na `(` mtawalia.

#### Example Method Declaration
```objectivec
- (NSString *)processString:(id)input withOptions:(char *)options andError:(id)error;
```
Selector itakuwa `processString:withOptions:andError:`

#### Type Encoding

- `id` huwakilishwa kama `@`
- `char *` huwakilishwa kama `*`

Type encoding kamili ya method ni:
```less
@24@0:8@16*20^@24
```
#### Uchanganuzi wa Kina

1. Return Type (`NSString *`): Imewekewa msimbo wa `@` wenye urefu wa 24
2. `self` (object instance): Imewekewa msimbo wa `@`, kwenye offset 0
3. `_cmd` (selector): Imewekewa msimbo wa `:`, kwenye offset 8
4. First argument (`char * input`): Imewekewa msimbo wa `*`, kwenye offset 16
5. Second argument (`NSDictionary * options`): Imewekewa msimbo wa `@`, kwenye offset 20
6. Third argument (`NSError ** error`): Imewekewa msimbo wa `^@`, kwenye offset 24

Kwa kutumia selector pamoja na encoding, unaweza kuunda upya method.

### Madarasa

Madarasa katika Objective-C ni C structs zenye properties, method pointers, n.k. Inawezekana kupata struct `objc_class` katika [**source code**](https://opensource.apple.com/source/objc4/objc4-756.2/runtime/objc-runtime-new.h.auto.html):
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
Class hii hutumia baadhi ya biti za sehemu ya `isa` kuashiria taarifa kuhusu class.

Kisha, struct huwa na pointer inayoelekeza kwenye struct `class_ro_t` iliyohifadhiwa kwenye disk, ambayo ina attributes za class kama vile jina lake, base methods, properties na instance variables. Wakati wa runtime, structure ya ziada `class_rw_t` hutumiwa ikiwa na pointers zinazoweza kubadilishwa, kama vile methods, protocols na properties.

{{#ref}}
../macos-basic-objective-c.md
{{#endref}}

---

## Uwakilishi wa kisasa wa objects kwenye memory (arm64e, tagged pointers, Swift)

### `isa` isiyo pointer na Pointer Authentication (arm64e)

Kwenye Apple Silicon na runtimes za hivi karibuni, Objective-C `isa` si pointer ghafi ya class kila wakati. Kwenye arm64e ni packed structure ambayo pia inaweza kubeba Pointer Authentication Code (PAC). Kulingana na platform, inaweza kuwa na fields kama `nonpointer`, `has_assoc`, `weakly_referenced`, `extra_rc`, pamoja na class pointer yenyewe (ikiwa ime-shift au imesainiwa). Hii inamaanisha kuwa kudereference bila kuchunguza bytes 8 za kwanza za Objective-C object hakutatoa kila wakati pointer halali ya `Class`.<sup>[[2]](#references)</sup>

Vidokezo vya vitendo unapodebug kwenye arm64e:

- LLDB kwa kawaida huondoa PAC bits kwa ajili yako unapochapisha Objective-C objects kwa `po`, lakini unapofanya kazi na raw pointers unaweza kuhitaji kuondoa authentication mwenyewe:

```lldb
(lldb) expr -l objc++ -- #include <ptrauth.h>
(lldb) expr -l objc++ -- void *raw = ptrauth_strip((void*)0x000000016f123abc, ptrauth_key_asda);
(lldb) expr -l objc++ -O -- (Class)object_getClass((id)raw)
```

- Function/data pointers nyingi kwenye Mach-O zitakuwa ndani ya `__AUTH`/`__AUTH_CONST` na zitahitaji authentication kabla ya kutumiwa. Ikiwa una-interpose au una-re-bind (kwa mfano, kwa mtindo wa fishhook), hakikisha pia unashughulikia `__auth_got` pamoja na `__got` ya zamani.

Kwa uchambuzi wa kina kuhusu language/ABI guarantees na intrinsics za `<ptrauth.h>` zinazopatikana kutoka Clang/LLVM, angalia reference iliyo mwishoni mwa ukurasa huu.<sup>[[1]](#references)</sup>

### Tagged pointer objects

Baadhi ya classes za Foundation huepuka heap allocation kwa kusimba payload ya object moja kwa moja ndani ya pointer value (tagged pointers). Utambuzi hutofautiana kulingana na platform (kwa mfano, most-significant bit kwenye arm64, na least-significant bit kwenye x86_64 macOS). Tagged objects hazina `isa` ya kawaida iliyohifadhiwa kwenye memory; runtime hutatua class kutokana na tag bits.<sup>[[2]](#references)</sup> Unapokagua `id` values zisizojulikana:

- Tumia runtime APIs badala ya kuchunguza field ya `isa`: `object_getClass(obj)` / `[obj class]`.
- Kwenye LLDB, `po (id)0xADDR` itachapisha tagged pointer instances kwa usahihi kwa sababu runtime huwasilishwa ili kutatua class.

### Swift heap objects na metadata

Pure Swift classes pia ni objects zenye header inayoelekeza kwenye Swift metadata (si Objective-C `isa`). Ili kufanya introspection ya live Swift processes bila kuzibadilisha, unaweza kutumia Swift toolchain ya `swift-inspect`, ambayo hutumia Remote Mirror library kusoma runtime metadata:
```bash
# Xcode toolchain (or Swift.org toolchain) provides swift-inspect
swift-inspect dump-raw-metadata <pid-or-name>
swift-inspect dump-arrays <pid-or-name>
# On Darwin additionally:
swift-inspect dump-concurrency <pid-or-name>
```
Hii ni muhimu sana kwa kuchora ramani ya Swift heap objects na protocol conformances wakati wa kureverse apps mchanganyiko za Swift/ObjC.

---

## Karatasi ya kumbukumbu ya runtime inspection (LLDB / Frida)

### LLDB

- Chapisha object au class kutoka kwenye raw pointer:
```lldb
(lldb) expr -l objc++ -O -- (id)0x0000000101234560
(lldb) expr -l objc++ -O -- (Class)object_getClass((id)0x0000000101234560)
```
- Kagua class ya Objective-C kutoka kwa pointer ya `self` ya object method wakati wa breakpoint:
```lldb
(lldb) br se -n '-[NSFileManager fileExistsAtPath:]'
(lldb) r
... breakpoint hit ...
(lldb) po (id)$x0                 # self
(lldb) expr -l objc++ -O -- (Class)object_getClass((id)$x0)
```
- Dump sehemu zinazobeba metadata ya Objective-C (kumbuka: nyingi sasa ziko katika `__DATA_CONST` / `__AUTH_CONST`):
```lldb
(lldb) image dump section --section __DATA_CONST.__objc_classlist
(lldb) image dump section --section __DATA_CONST.__objc_selrefs
(lldb) image dump section --section __AUTH_CONST.__auth_got
```
- Soma memory ya object ya class inayojulikana ili kufanya pivot kwenda `class_ro_t` / `class_rw_t` wakati wa kureverse method lists:
```lldb
(lldb) image lookup -r -n _OBJC_CLASS_$_NSFileManager
(lldb) memory read -fx -s8 0xADDRESS_OF_CLASS_OBJECT
```
### Frida (Objective-C na Swift)

Frida hutoa bridges za kiwango cha juu za runtime ambazo ni muhimu sana kwa kugundua na ku-instrument objects zilizo hai bila symbols:

- Enumerate classes na methods, tambua majina halisi ya classes wakati wa runtime, na intercept selectors za Objective-C:
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
- Swift bridge: orodhesha aina za Swift na kuingiliana na instances za Swift (inahitaji Frida ya hivi karibuni; ni muhimu sana kwenye targets za Apple Silicon).

---

## Marejeo


- [1] [Clang/LLVM: Pointer Authentication and the ptrauth.h intrinsics (arm64e ABI)](https://clang.llvm.org/docs/PointerAuthentication.html)
- [2] [Apple objc runtime headers - objc-object.h (tagged pointers, non‑pointer isa, etc.)](https://opensource.apple.com/source/objc4/objc4-818.2/runtime/objc-object.h.auto.html)

{{#include ../../../banners/hacktricks-training.md}}
