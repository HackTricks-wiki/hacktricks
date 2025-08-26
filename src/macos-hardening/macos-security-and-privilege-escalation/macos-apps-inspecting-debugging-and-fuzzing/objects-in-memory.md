# Objekti u memoriji

{{#include ../../../banners/hacktricks-training.md}}

## CFRuntimeClass

CF* objekti potiču iz CoreFoundation, koja obezbeđuje više od 50 klasa objekata poput `CFString`, `CFNumber` ili `CFAllocator`.

Sve ove klase su instance klase `CFRuntimeClass`, koja kada se pozove vraća indeks u `__CFRuntimeClassTable`. CFRuntimeClass je definisana u [**CFRuntime.h**](https://opensource.apple.com/source/CF/CF-1153.18/CFRuntime.h.auto.html):
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

### Memorijske sekcije koje se koriste

Većina podataka koje koristi Objective‑C runtime menjaće se tokom izvršavanja, zato koristi niz sekcija iz Mach‑O `__DATA` familije segmenata u memoriji. Istorijski su to uključivale:

- `__objc_msgrefs` (`message_ref_t`): referencije poruka
- `__objc_ivar` (`ivar`): instancijalne promenljive
- `__objc_data` (`...`): promenljivi podaci
- `__objc_classrefs` (`Class`): referencije klasa
- `__objc_superrefs` (`Class`): referencije nadklasa
- `__objc_protorefs` (`protocol_t *`): referencije protokola
- `__objc_selrefs` (`SEL`): referencije selektora
- `__objc_const` (`...`): r/o podaci klase i drugi (nadamo se) konstantni podaci
- `__objc_imageinfo` (`version, flags`): koristi se tokom učitavanja image‑a: Version trenutno `0`; Flags specificiraju podršku za preoptimized GC, itd.
- `__objc_protolist` (`protocol_t *`): lista protokola
- `__objc_nlcatlist` (`category_t`): pokazivač na Non-Lazy Categories definisane u ovom binarnom fajlu
- `__objc_catlist` (`category_t`): pokazivač na Categories definisane u ovom binarnom fajlu
- `__objc_nlclslist` (`classref_t`): pokazivač na Non-Lazy Objective‑C klase definisane u ovom binarnom fajlu
- `__objc_classlist` (`classref_t`): pokazivači na sve Objective‑C klase definisane u ovom binarnom fajlu

Takođe koristi nekoliko sekcija u `__TEXT` segmentu za skladištenje konstanti:

- `__objc_methname` (C‑String): imena metoda
- `__objc_classname` (C‑String): imena klasa
- `__objc_methtype` (C‑String): tipovi metoda

Moderni macOS/iOS (posebno na Apple Silicon) takođe smeštaju Objective‑C/Swift metapodatke u:

- `__DATA_CONST`: nepromenljivi Objective‑C metapodaci koji se mogu deliti read‑only između procesa (na primer, mnoge `__objc_*` liste sada žive ovde).
- `__AUTH` / `__AUTH_CONST`: segmenti koji sadrže pokazivače koji moraju biti autentifikovani pri učitavanju ili u vreme upotrebe na arm64e (Pointer Authentication). Takođe ćete videti `__auth_got` u `__AUTH_CONST` umesto legacy `__la_symbol_ptr`/`__got` samo. Kada instrumentujete ili hook‑ujete, imajte na umu da uzmete u obzir i `__got` i `__auth_got` unose u modernim binarnima.

Za pozadinu o dyld pre‑optimizaciji (npr. selector uniquing i prekomputacija klasa/protokola) i zašto su mnoge od ovih sekcija "već fikse‑ovane" kada dolaze iz shared cache‑a, pogledajte Apple `objc-opt` izvore i napomene o dyld shared cache‑u. Ovo utiče na mesto i način na koji možete patch‑ovati metapodatke u runtime‑u.

{{#ref}}
../macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.md
{{#endref}}

### Kodiranje tipova

Objective‑C koristi mangling da enkodira tipove selektora i promenljivih jednostavnih i složenih tipova:

- Primitive types koriste prvo slovo tipa `i` za `int`, `c` za `char`, `l` za `long`... i koriste veliko slovo u slučaju da su unsigned (`L` za `unsigned long`).
- Drugi tipovi podataka koriste druga slova ili simbole kao što su `q` za `long long`, `b` za bitfields, `B` za booleans, `#` za klase, `@` za `id`, `*` za `char *`, `^` za generičke pokazivače i `?` za nedefinisano.
- Nizovi, strukture i unije koriste `[` , `{` i `(` respektivno.

#### Primer deklaracije metode
```objectivec
- (NSString *)processString:(id)input withOptions:(char *)options andError:(id)error;
```
Selektor bi bio `processString:withOptions:andError:`

#### Kodiranje tipova

- `id` je kodirano kao `@`
- `char *` je kodirano kao `*`

Kompletno kodiranje tipova za metodu je:
```less
@24@0:8@16*20^@24
```
#### Detaljna analiza

1. Return Type (`NSString *`): Encoded as `@` with length 24
2. `self` (instanca objekta): Kodirano kao `@`, na offsetu 0
3. `_cmd` (selektor): Kodirano kao `:`, na offsetu 8
4. Prvi argument (`char * input`): Kodirano kao `*`, na offsetu 16
5. Drugi argument (`NSDictionary * options`): Kodirano kao `@`, na offsetu 20
6. Treći argument (`NSError ** error`): Kodirano kao `^@`, na offsetu 24

Sa selektorom + enkodiranjem možete rekonstruisati metodu.

### Klase

Klase u Objective‑C su C strukture sa svojstvima, pokazivačima na metode, itd. Moguće je pronaći strukturu `objc_class` u [**source code**](https://opensource.apple.com/source/objc4/objc4-756.2/runtime/objc-runtime-new.h.auto.html):
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
Ova klasa koristi neke bitove polja `isa` da označi informacije o klasi.

Zatim, struct ima pokazivač na struct `class_ro_t` pohranjen na disku koji sadrži atribute klase kao što su njeno ime, osnovne metode, properties i instance variables. Tokom runtime‑a koristi se dodatna struktura `class_rw_t` koja sadrži pokazivače koji se mogu menjati, kao što su methods, protocols, properties.

{{#ref}}
../macos-basic-objective-c.md
{{#endref}}

---

## Modern object representations in memory (arm64e, tagged pointers, Swift)

### Non‑pointer `isa` and Pointer Authentication (arm64e)

Na Apple Silicon i novijim runtime‑ima Objective‑C `isa` nije uvek običan pokazivač na klasu. Na arm64e to je upakovana struktura koja može nositi i Pointer Authentication Code (PAC). U zavisnosti od platforme može uključivati polja poput `nonpointer`, `has_assoc`, `weakly_referenced`, `extra_rc`, i sam pokazivač na klasu (shifted ili signed). To znači da slepo dereferenciranje prvih 8 bajtova Objective‑C objekta neće uvek dati važeći `Class` pokazivač.

Praktične napomene pri debugovanju na arm64e:

- LLDB će obično ukloniti PAC bitove za vas kada štampa Objective‑C objekte pomoću `po`, ali kada radite sa raw pokazivačima možda ćete morati ručno da uklonite autentikaciju:

```lldb
(lldb) expr -l objc++ -- #include <ptrauth.h>
(lldb) expr -l objc++ -- void *raw = ptrauth_strip((void*)0x000000016f123abc, ptrauth_key_asda);
(lldb) expr -l objc++ -O -- (Class)object_getClass((id)raw)
```

- Mnogi pokazivači na funkcije/podatke u Mach‑O biće smešteni u `__AUTH`/`__AUTH_CONST` i zahtevaju autentikaciju pre upotrebe. Ako interponujete ili re‑bindingujete (npr. fishhook‑style), obavezno obradite i `__auth_got` pored legacy `__got`.

Za dubinsko razumevanje garantija jezika/ABI i `<ptrauth.h>` intrinsičnih funkcija dostupnih iz Clang/LLVM, pogledajte referencu na kraju ove stranice.

### Tagged pointer objects

Neke Foundation klase izbegavaju alokaciju na heap‑u enkodiranjem payload‑a objekta direktno u vrednost pokazivača (tagged pointers). Detekcija se razlikuje po platformi (npr. most‑significant bit na arm64, least‑significant na x86_64 macOS). Tagged objekti nemaju regularan `isa` pohranjen u memoriji; runtime rešava klasu iz tag bitova. Pri inspekciji proizvoljnih `id` vrednosti:

- Koristite runtime API‑je umesto da „poke‑ujete“ polje `isa`: `object_getClass(obj)` / `[obj class]`.
- U LLDB‑u, samo `po (id)0xADDR` će ispravno odštampati tagged pointer instance jer se runtime konsultuje da reši klasu.

### Swift heap objects and metadata

Čiste Swift klase su takođe objekti sa header‑om koji pokazuje na Swift metadata (ne Objective‑C `isa`). Da biste introspektovali žive Swift procese bez njihovog menjanja možete koristiti Swift toolchain‑ov `swift-inspect`, koji koristi Remote Mirror biblioteku za čitanje runtime metadata:
```bash
# Xcode toolchain (or Swift.org toolchain) provides swift-inspect
swift-inspect dump-raw-metadata <pid-or-name>
swift-inspect dump-arrays <pid-or-name>
# On Darwin additionally:
swift-inspect dump-concurrency <pid-or-name>
```
Ovo je veoma korisno za mapiranje Swift heap objekata i usklađenosti sa protokolima pri reverziranju mešanih Swift/ObjC aplikacija.

---

## Kratka referenca za inspekciju runtime-a (LLDB / Frida)

### LLDB

- Ispiši objekat ili klasu iz sirovog pokazivača:
```lldb
(lldb) expr -l objc++ -O -- (id)0x0000000101234560
(lldb) expr -l objc++ -O -- (Class)object_getClass((id)0x0000000101234560)
```
- Pregledajte Objective‑C klasu iz pokazivača na `self` u metodi objekta u breakpointu:
```lldb
(lldb) br se -n '-[NSFileManager fileExistsAtPath:]'
(lldb) r
... breakpoint hit ...
(lldb) po (id)$x0                 # self
(lldb) expr -l objc++ -O -- (Class)object_getClass((id)$x0)
```
- Dump sekcije koje sadrže Objective‑C metapodatke (napomena: mnoge se sada nalaze u `__DATA_CONST` / `__AUTH_CONST`):
```lldb
(lldb) image dump section --section __DATA_CONST.__objc_classlist
(lldb) image dump section --section __DATA_CONST.__objc_selrefs
(lldb) image dump section --section __AUTH_CONST.__auth_got
```
- Pročitaj memoriju poznatog objekta klase da bi pivot to `class_ro_t` / `class_rw_t` pri reverziranju listi metoda:
```lldb
(lldb) image lookup -r -n _OBJC_CLASS_$_NSFileManager
(lldb) memory read -fx -s8 0xADDRESS_OF_CLASS_OBJECT
```
### Frida (Objective‑C and Swift)

Frida pruža visokonivozne runtime mostove koji su vrlo praktični za otkrivanje i instrumentovanje aktivnih objekata bez simbola:

- Nabrajanje klasa i metoda, rešavanje stvarnih imena klasa u runtime-u, i presretanje Objective‑C selektora:
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
- Swift bridge: enumeriše Swift types i omogućava interakciju sa Swift instances (zahteva noviju Frida; veoma korisno na Apple Silicon targets).

---

## Reference

- Clang/LLVM: Pointer Authentication and the `<ptrauth.h>` intrinsics (arm64e ABI). https://clang.llvm.org/docs/PointerAuthentication.html
- Apple objc runtime headers (tagged pointers, non‑pointer `isa`, etc.) e.g., `objc-object.h`. https://opensource.apple.com/source/objc4/objc4-818.2/runtime/objc-object.h.auto.html

{{#include ../../../banners/hacktricks-training.md}}
