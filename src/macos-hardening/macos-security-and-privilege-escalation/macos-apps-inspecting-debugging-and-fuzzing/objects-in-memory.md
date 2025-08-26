# Objekte in geheue

{{#include ../../../banners/hacktricks-training.md}}

## CFRuntimeClass

CF*-objekte kom van CoreFoundation, wat meer as 50 klasse verskaf, soos `CFString`, `CFNumber` of `CFAllocator`.

Al hierdie klasse is instansies van die klas `CFRuntimeClass`, wat wanneer dit aangeroep word 'n indeks na die `__CFRuntimeClassTable` teruggee. Die CFRuntimeClass is gedefinieer in [**CFRuntime.h**](https://opensource.apple.com/source/CF/CF-1153.18/CFRuntime.h.auto.html):
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

Die meeste van die data wat deur die Objective‑C runtime gebruik word, sal tydens uitvoering verander, daarom gebruik dit 'n aantal seksies van die Mach‑O `__DATA` familie van segments in geheue. Voorheen het dit die volgende ingesluit:

- `__objc_msgrefs` (`message_ref_t`): boodskapverwysings
- `__objc_ivar` (`ivar`): instansie veranderlikes
- `__objc_data` (`...`): veranderlike data
- `__objc_classrefs` (`Class`): klasverwysings
- `__objc_superrefs` (`Class`): superklasverwysings
- `__objc_protorefs` (`protocol_t *`): protokolverwysings
- `__objc_selrefs` (`SEL`): selektorverwysings
- `__objc_const` (`...`): klas r/o data en ander (hopelik) konstante data
- `__objc_imageinfo` (`version, flags`): word gebruik tydens image load: weergawe tans `0`; vlagte spesifiseer voorafgeoptimaliseerde GC-ondersteuning, ens.
- `__objc_protolist` (`protocol_t *`): protokollys
- `__objc_nlcatlist` (`category_t`): wysiger na Non-Lazy Categories gedefinieer in hierdie binêr
- `__objc_catlist` (`category_t`): wysiger na Categories gedefinieer in hierdie binêr
- `__objc_nlclslist` (`classref_t`): wysiger na Non-Lazy Objective‑C klases gedefinieer in hierdie binêr
- `__objc_classlist` (`classref_t`): wysigers na alle Objective‑C klases gedefinieer in hierdie binêr

Dit gebruik ook 'n paar seksies in die `__TEXT` segment om konstantes te stoor:

- `__objc_methname` (C‑String): metode name
- `__objc_classname` (C‑String): klasname
- `__objc_methtype` (C‑String): metode tipes

Moderne macOS/iOS (veral op Apple Silicon) plaas ook Objective‑C/Swift metadata in:

- `__DATA_CONST`: onveranderlike Objective‑C metadata wat as slegs‑lees oor prosesse gedeel kan word (byvoorbeeld baie `__objc_*` lyste woon nou hier).
- `__AUTH` / `__AUTH_CONST`: segmente wat wysigers bevat wat geverifieer moet word tydens laai of gebruikstyd op arm64e (Pointer Authentication). Jy sal ook `__auth_got` in `__AUTH_CONST` sien in plaas van die klassieke `__la_symbol_ptr`/`__got` alleenlik. Wanneer jy instrumenteer of hook, onthou om rekening te hou met beide `__got` en `__auth_got` inskrywings in moderne binaries.

Vir agtergrond oor dyld vooraf‑optimalisering (bv. selector uniquing en class/protocol precomputation) en waarom baie van hierdie seksies alreeds "aangepas" is wanneer hulle uit die shared cache kom, kyk na die Apple `objc-opt` sources en dyld shared cache notas. Dit beïnvloed waar en hoe jy metadata tydens uitvoering kan aanpas.

{{#ref}}
../macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.md
{{#endref}}

### Type Encoding

Objective‑C gebruik naam‑mangling om selektor- en veranderlike tipes van eenvoudige en komplekse tipes te enkodeer:

- Primêre tipes gebruik die eerste letter van die tipe: `i` vir `int`, `c` vir `char`, `l` vir `long` ... en gebruik die hoofletter indien dit unsigned is (`L` vir `unsigned long`).
- Ander datatipes gebruik ander letters of simbole soos `q` vir `long long`, `b` vir bitfields, `B` vir booleans, `#` vir classes, `@` vir `id`, `*` vir `char *`, `^` vir generiese wysigers en `?` vir undefined.
- Arrays, strukture en unies gebruik onderskeidelik `[`, `{` en `(`.

#### Example Method Declaration
```objectivec
- (NSString *)processString:(id)input withOptions:(char *)options andError:(id)error;
```
Die selector sou wees `processString:withOptions:andError:`

#### Tipe-kodering

- `id` word gekodeer as `@`
- `char *` word gekodeer as `*`

Die volledige tipe-kodering vir die metode is:
```less
@24@0:8@16*20^@24
```
#### Gedetailleerde ontleding

1. Retuurtipe (`NSString *`): Gekodeer as `@` met lengte 24  
2. `self` (objekinstansie): Gekodeer as `@`, by offset 0  
3. `_cmd` (selekteerder): Gekodeer as `:`, by offset 8  
4. Eerste argument (`char * input`): Gekodeer as `*`, by offset 16  
5. Tweede argument (`NSDictionary * options`): Gekodeer as `@`, by offset 20  
6. Derde argument (`NSError ** error`): Gekodeer as `^@`, by offset 24

Met die selekteerder + die kodering kan jy die metode herbou.

### Klasse

Klasse in Objective‑C is C-strukture met eiendomme, metode-aanwysers, ens. Dit is moontlik om die struktuur `objc_class` te vind in die [**source code**](https://opensource.apple.com/source/objc4/objc4-756.2/runtime/objc-runtime-new.h.auto.html):
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

## Moderne objekvoorstellings in geheue (arm64e, tagged pointers, Swift)

### Nie‑pointer `isa` en Pointer Authentication (arm64e)

Op Apple Silicon en onlangse runtimes is die Objective‑C `isa` nie altyd 'n rou klas-pointer nie. Op arm64e is dit 'n gepakte struktuur wat ook 'n Pointer Authentication Code (PAC) kan dra. Afhangend van die platform kan dit velde insluit soos `nonpointer`, `has_assoc`, `weakly_referenced`, `extra_rc`, en die klas pointer self (shifted or signed). Dit beteken dat blinde dereferensiering van die eerste 8 bytes van 'n Objective‑C objek nie altyd 'n geldige `Class` pointer sal lewer nie.

Praktiese notas wanneer jy op arm64e debug:

- LLDB verwyder gewoonlik PAC‑bits vir jou wanneer dit Objective‑C objekte met `po` druk, maar wanneer jy met rou pointers werk mag jy die authenticatie handmatig moet verwyder:

```lldb
(lldb) expr -l objc++ -- #include <ptrauth.h>
(lldb) expr -l objc++ -- void *raw = ptrauth_strip((void*)0x000000016f123abc, ptrauth_key_asda);
(lldb) expr -l objc++ -O -- (Class)object_getClass((id)raw)
```

- Baie function/data pointers in Mach‑O sal in `__AUTH`/`__AUTH_CONST` woon en vereis authenticatie voor gebruik. As jy interposeer of herbind (bv. fishhook‑styl), verseker dat jy ook `__auth_got` hanteer benewens die ouer `__got`.

Vir 'n diepgaande uiteensetting van taal-/ABI‑waarborge en die `<ptrauth.h>` intrinsics wat beskikbaar is via Clang/LLVM, sien die verwysing aan die einde van hierdie bladsy.

### Tagged pointer-objekte

Sommige Foundation‑klasse vermy heap‑allokasie deur die objek se payload direk in die pointer‑waarde te enkodeer (tagged pointers). Detectie verskil per platform (bv. die meest‑signifkante bit op arm64, die minste‑signifkante op x86_64 macOS). Tagged objects het nie 'n normale `isa` in geheue gestoor nie; die runtime los die klas op vanaf die tag‑bits. Wanneer jy willekeurige `id` waardes inspekteer:

- Gebruik runtime APIs in plaas daarvan om die `isa`-veld te toetel: `object_getClass(obj)` / `[obj class]`.
- In LLDB sal bloot `po (id)0xADDR` tagged pointer‑instances korrek druk omdat die runtime geraadpleeg word om die klas op te los.

### Swift heap‑objekte en metadata

Suiwer Swift‑klasse is ook objekte met 'n header wat na Swift‑metadata wys (nie Objective‑C `isa` nie). Om live Swift‑prosesse te introspekteer sonder om hulle te wysig, kan jy die Swift toolchain se `swift-inspect` gebruik, wat die Remote Mirror‑biblioteek gebruik om runtime‑metadata te lees:
```bash
# Xcode toolchain (or Swift.org toolchain) provides swift-inspect
swift-inspect dump-raw-metadata <pid-or-name>
swift-inspect dump-arrays <pid-or-name>
# On Darwin additionally:
swift-inspect dump-concurrency <pid-or-name>
```
Dit is baie nuttig om Swift heap objects en protocol conformances in kaart te bring wanneer jy gemengde Swift/ObjC apps reverse.

---

## Runtime-inspeksie cheatsheet (LLDB / Frida)

### LLDB

- Druk object of klas vanaf 'n rou pointer:
```lldb
(lldb) expr -l objc++ -O -- (id)0x0000000101234560
(lldb) expr -l objc++ -O -- (Class)object_getClass((id)0x0000000101234560)
```
- Inspekteer Objective‑C klas vanaf 'n pointer na die `self` van 'n objectmetode in 'n breakpoint:
```lldb
(lldb) br se -n '-[NSFileManager fileExistsAtPath:]'
(lldb) r
... breakpoint hit ...
(lldb) po (id)$x0                 # self
(lldb) expr -l objc++ -O -- (Class)object_getClass((id)$x0)
```
- Dump sections wat Objective‑C metadata dra (let wel: baie is nou in `__DATA_CONST` / `__AUTH_CONST`):
```lldb
(lldb) image dump section --section __DATA_CONST.__objc_classlist
(lldb) image dump section --section __DATA_CONST.__objc_selrefs
(lldb) image dump section --section __AUTH_CONST.__auth_got
```
- Lees geheue vir 'n bekende klasobjek om te pivot na `class_ro_t` / `class_rw_t` wanneer reversing method lists:
```lldb
(lldb) image lookup -r -n _OBJC_CLASS_$_NSFileManager
(lldb) memory read -fx -s8 0xADDRESS_OF_CLASS_OBJECT
```
### Frida (Objective‑C and Swift)

Frida bied hoëvlak runtime-brûe wat baie handig is om lewende objekte sonder simbole te ontdek en te instrumenteer:

- Enumereer klasse en metodes, los werklike klasname tydens runtime op, en onderskep Objective‑C selectors:
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
- Swift-brug: lys Swift-tipes op en interageer met Swift-instansies (vereis 'n onlangse Frida; baie nuttig op Apple Silicon-teikens).

---

## Verwysings

- Clang/LLVM: Pointer Authentication and the `<ptrauth.h>` intrinsics (arm64e ABI). https://clang.llvm.org/docs/PointerAuthentication.html
- Apple objc runtime headers (tagged pointers, non‑pointer `isa`, etc.) e.g., `objc-object.h`. https://opensource.apple.com/source/objc4/objc4-818.2/runtime/objc-object.h.auto.html

{{#include ../../../banners/hacktricks-training.md}}
