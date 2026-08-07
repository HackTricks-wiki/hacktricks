# Obj ekte in geheue

{{#include ../../../banners/hacktricks-training.md}}

## CFRuntimeClass

CF*-objekte kom van CoreFoundation, wat meer as 50 klasse objekte verskaf, soos `CFString`, `CFNumber` of `CFAllocator`.

Al hierdie klasse is instansies van die klas `CFRuntimeClass`, wat, wanneer dit aangeroep word, 'n indeks na die `__CFRuntimeClassTable` terugstuur. Die CFRuntimeClass word gedefinieer in [**CFRuntime.h**](https://opensource.apple.com/source/CF/CF-1153.18/CFRuntime.h.auto.html):
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

### Geheue-afdelings wat gebruik word

Die meeste van die data wat deur die Objective-C runtime gebruik word, sal tydens uitvoering verander; daarom gebruik dit ’n aantal afdelings uit die Mach-O `__DATA`-familie van segmente in die geheue. Histories het dit die volgende ingesluit:

- `__objc_msgrefs` (`message_ref_t`): Message-verwysings
- `__objc_ivar` (`ivar`): Instance-veranderlikes
- `__objc_data` (`...`): Veranderlike data
- `__objc_classrefs` (`Class`): Klasverwysings
- `__objc_superrefs` (`Class`): Superklasverwysings
- `__objc_protorefs` (`protocol_t *`): Protocol-verwysings
- `__objc_selrefs` (`SEL`): Selector-verwysings
- `__objc_const` (`...`): Klas-leesalleen-data en ander (hopelik) konstante data
- `__objc_imageinfo` (`version, flags`): Word tydens image-laai gebruik: Weergawe tans `0`; Flags spesifiseer voorafgeoptimaliseerde GC-ondersteuning, ens.
- `__objc_protolist` (`protocol_t *`): Protokollys
- `__objc_nlcatlist` (`category_t`): Wyser na Non-Lazy Categories wat in hierdie binary gedefinieer is
- `__objc_catlist` (`category_t`): Wyser na Categories wat in hierdie binary gedefinieer is
- `__objc_nlclslist` (`classref_t`): Wyser na Non-Lazy Objective-C-klasse wat in hierdie binary gedefinieer is
- `__objc_classlist` (`classref_t`): Wysers na alle Objective-C-klasse wat in hierdie binary gedefinieer is

Dit gebruik ook ’n paar afdelings in die `__TEXT`-segment om konstantes te stoor:

- `__objc_methname` (C-String): Method-name
- `__objc_classname` (C-String): Klasname
- `__objc_methtype` (C-String): Method-tipes

Moderne macOS/iOS (veral op Apple Silicon) plaas ook Objective-C/Swift-metadata in:

- `__DATA_CONST`: Onveranderlike Objective-C-metadata wat read-only tussen prosesse gedeel kan word (byvoorbeeld, baie `__objc_*`-lyste is nou hier).
- `__AUTH` / `__AUTH_CONST`: Segmente wat wysers bevat wat tydens laai of gebruik op arm64e geverifieer moet word (Pointer Authentication). Jy sal ook `__auth_got` in `__AUTH_CONST` sien in plaas van slegs die legacy `__la_symbol_ptr`/`__got`. Wanneer jy instrumenteer of hook, onthou om beide `__got`- en `__auth_got`-inskrywings in moderne binaries in ag te neem.

Vir agtergrond oor dyld-pre-optimalisering (byvoorbeeld selector-uniquing en klas-/protokolvoorberekening), en waarom baie van hierdie afdelings reeds "reggestel" is wanneer hulle uit die shared cache kom, raadpleeg die Apple `objc-opt`-bronkode en notas oor die dyld shared cache. Dit beïnvloed waar en hoe jy metadata tydens runtime kan patch.

{{#ref}}
../macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.md
{{#endref}}

### Tipe-enkodering

Objective-C gebruik mangling om selector- en veranderlike-tipes van eenvoudige en komplekse tipes te enkodeer:

- Primitiewe tipes gebruik hul eerste letter van die tipe: `i` vir `int`, `c` vir `char`, `l` vir `long`... en gebruik die hoofletter wanneer dit unsigned is (`L` vir `unsigned long`).
- Ander datatipes gebruik ander letters of simbole, soos `q` vir `long long`, `b` vir bitfields, `B` vir booleans, `#` vir klasse, `@` vir `id`, `*` vir `char *`, `^` vir generiese wysers en `?` vir ongedefinieerde tipes.
- Arrays, strukture en unions gebruik onderskeidelik `[`, `{` en `(`.

#### Voorbeeld van ’n Method-deklarasie
```objectivec
- (NSString *)processString:(id)input withOptions:(char *)options andError:(id)error;
```
Die selector sal `processString:withOptions:andError:` wees

#### Tipe-enkodering

- `id` word as `@` geënkodeer
- `char *` word as `*` geënkodeer

Die volledige tipe-enkodering vir die metode is:
```less
@24@0:8@16*20^@24
```
#### Gedetailleerde uiteensetting

1. Return Type (`NSString *`): Geënkodeer as `@` met lengte 24
2. `self` (object instance): Geënkodeer as `@`, by offset 0
3. `_cmd` (selector): Geënkodeer as `:`, by offset 8
4. First argument (`char * input`): Geënkodeer as `*`, by offset 16
5. Second argument (`NSDictionary * options`): Geënkodeer as `@`, by offset 20
6. Third argument (`NSError ** error`): Geënkodeer as `^@`, by offset 24

Met die selector + die encoding kan jy die method rekonstrueer.

### Classes

Classes in Objective‑C is C structs met properties, method pointers, ens. Dit is moontlik om die struct `objc_class` in die [**source code**](https://opensource.apple.com/source/objc4/objc4-756.2/runtime/objc-runtime-new.h.auto.html) te vind:
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
Hierdie klas gebruik sommige stukkies van die `isa`-veld om inligting oor die klas aan te dui.

Daarna het die struct 'n pointer na die struct `class_ro_t` wat op skyf gestoor word en eienskappe van die klas bevat, soos sy naam, basismetodes, properties en instance variables. Tydens runtime word 'n bykomende struktuur `class_rw_t` gebruik wat pointers bevat wat gewysig kan word, soos metodes, protokolle en properties.

{{#ref}}
../macos-basic-objective-c.md
{{#endref}}

---

## Moderne objekvoorstellings in geheue (arm64e, tagged pointers, Swift)

### Nie-pointer `isa` en Pointer Authentication (arm64e)

Op Apple Silicon en onlangse runtimes is die Objective-C `isa` nie altyd 'n rou klas-pointer nie. Op arm64e is dit 'n gepakte struktuur wat ook 'n Pointer Authentication Code (PAC) kan bevat. Afhangend van die platform kan dit velde soos `nonpointer`, `has_assoc`, `weakly_referenced`, `extra_rc`, en die klas-pointer self bevat (geskuif of onderteken). Dit beteken dat die eerste 8 bytes van 'n Objective-C-objek nie altyd blindelings gedereferensieer kan word om 'n geldige `Class`-pointer te verkry nie.<sup>[[2]](#references)</sup>

Praktiese notas wanneer jy op arm64e debug:

- LLDB sal gewoonlik PAC-bisse vir jou verwyder wanneer jy Objective-C-objekte met `po` druk, maar wanneer jy met rou pointers werk, sal jy moontlik authentication handmatig moet verwyder:

```lldb
(lldb) expr -l objc++ -- #include <ptrauth.h>
(lldb) expr -l objc++ -- void *raw = ptrauth_strip((void*)0x000000016f123abc, ptrauth_key_asda);
(lldb) expr -l objc++ -O -- (Class)object_getClass((id)raw)
```

- Baie funksie-/data-pointers in Mach-O sal in `__AUTH`/`__AUTH_CONST` wees en authentication vereis voordat hulle gebruik kan word. As jy interposing of re-binding uitvoer (byvoorbeeld in fishhook-styl), maak seker dat jy ook `__auth_got` hanteer, benewens die legacy `__got`.

Vir 'n diepgaande bespreking van taal-/ABI-waarborge en die `<ptrauth.h>`-intrinsics wat van Clang/LLVM beskikbaar is, sien die verwysing aan die einde van hierdie bladsy.<sup>[[1]](#references)</sup>

### Tagged pointer-objekte

Sommige Foundation-klasse vermy heap-allocation deur die objek se payload direk in die pointer-waarde te enkodeer (tagged pointers). Opsporing verskil per platform (byvoorbeeld die mees betekenisvolle bietjie op arm64 en die minste betekenisvolle een op x86_64 macOS). Tagged objects het nie 'n gewone `isa` wat in geheue gestoor word nie; die runtime bepaal die klas vanaf die tag-bisse.<sup>[[2]](#references)</sup> Wanneer jy arbitrêre `id`-waardes inspekteer:

- Gebruik runtime-API's in plaas daarvan om aan die `isa`-veld te peuter: `object_getClass(obj)` / `[obj class]`.
- In LLDB sal `po (id)0xADDR` tagged pointer-instances korrek druk, omdat die runtime geraadpleeg word om die klas te bepaal.

### Swift heap-objekte en metadata

Suiwer Swift-klasse is ook objekte met 'n header wat na Swift-metadata wys (nie Objective-C `isa` nie). Om aktiewe Swift-prosesse te introspekteer sonder om hulle te wysig, kan jy die Swift toolchain se `swift-inspect` gebruik, wat die Remote Mirror-biblioteek benut om runtime-metadata te lees:
```bash
# Xcode toolchain (or Swift.org toolchain) provides swift-inspect
swift-inspect dump-raw-metadata <pid-or-name>
swift-inspect dump-arrays <pid-or-name>
# On Darwin additionally:
swift-inspect dump-concurrency <pid-or-name>
```
Dit is baie nuttig om Swift heap objects en protocol conformances te karteer wanneer gemengde Swift/ObjC-apps reverse word.

---

## Runtime-inspeksie cheatsheet (LLDB / Frida)

### LLDB

- Druk ’n object of class vanaf ’n raw pointer:
```lldb
(lldb) expr -l objc++ -O -- (id)0x0000000101234560
(lldb) expr -l objc++ -O -- (Class)object_getClass((id)0x0000000101234560)
```
- Inspekteer Objective-C-klas vanaf ’n pointer na ’n objekmetode se `self` in ’n breakpoint:
```lldb
(lldb) br se -n '-[NSFileManager fileExistsAtPath:]'
(lldb) r
... breakpoint hit ...
(lldb) po (id)$x0                 # self
(lldb) expr -l objc++ -O -- (Class)object_getClass((id)$x0)
```
- Dump seksies wat Objective-C metadata bevat (let wel: baie is nou in `__DATA_CONST` / `__AUTH_CONST`):
```lldb
(lldb) image dump section --section __DATA_CONST.__objc_classlist
(lldb) image dump section --section __DATA_CONST.__objc_selrefs
(lldb) image dump section --section __AUTH_CONST.__auth_got
```
- Lees geheue vir ’n bekende klasobjek om na `class_ro_t` / `class_rw_t` te pivot wanneer metodelyste reverse engineering word:
```lldb
(lldb) image lookup -r -n _OBJC_CLASS_$_NSFileManager
(lldb) memory read -fx -s8 0xADDRESS_OF_CLASS_OBJECT
```
### Frida (Objective-C en Swift)

Frida bied hoëvlak-runtime bridges wat baie handig is om lewendige objekte sonder symbols te ontdek en te instrumenteer:

- Enumereer klasse en metodes, bepaal werklike klassenname tydens runtime, en onderskep Objective-C selectors:
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
- Swift bridge: enumerateer Swift-tipes en interaksie met Swift-instansies (vereis onlangse Frida; baie nuttig op Apple Silicon-teikens).

---

## Verwysings


- [1] [Clang/LLVM: Pointer Authentication and the ptrauth.h intrinsics (arm64e ABI)](https://clang.llvm.org/docs/PointerAuthentication.html)
- [2] [Apple objc runtime headers - objc-object.h (tagged pointers, non‑pointer isa, etc.)](https://opensource.apple.com/source/objc4/objc4-818.2/runtime/objc-object.h.auto.html)

{{#include ../../../banners/hacktricks-training.md}}
