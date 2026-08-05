# Objekti u memoriji

{{#include ../../../banners/hacktricks-training.md}}

## CFRuntimeClass

CF* objekti potiču iz CoreFoundation-a, koji pruža više od 50 klasa objekata kao što su `CFString`, `CFNumber` ili `CFAllocator`.

Sve ove klase su instance klase `CFRuntimeClass`, koja, kada se pozove, vraća indeks u tabeli `__CFRuntimeClassTable`. CFRuntimeClass je definisana u [**CFRuntime.h**](https://opensource.apple.com/source/CF/CF-1153.18/CFRuntime.h.auto.html):
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

Većina podataka koje koristi Objective‑C runtime menja se tokom izvršavanja, pa zato u memoriji koristi više sekcija iz Mach‑O familije segmenata `__DATA`. Istorijski su one obuhvatale:

- `__objc_msgrefs` (`message_ref_t`): Reference na poruke
- `__objc_ivar` (`ivar`): Instance promenljive
- `__objc_data` (`...`): Promenljivi podaci
- `__objc_classrefs` (`Class`): Reference na klase
- `__objc_superrefs` (`Class`): Reference na superklase
- `__objc_protorefs` (`protocol_t *`): Reference na protokole
- `__objc_selrefs` (`SEL`): Reference na selektore
- `__objc_const` (`...`): Podaci klasa samo za čitanje i drugi (nadamo se) konstantni podaci
- `__objc_imageinfo` (`version, flags`): Koristi se tokom učitavanja image-a: Trenutna verzija je `0`; Flags navode podršku za preoptimized GC itd.
- `__objc_protolist` (`protocol_t *`): Lista protokola
- `__objc_nlcatlist` (`category_t`): Pokazivač na Non-Lazy Categories definisane u ovom binary-ju
- `__objc_catlist` (`category_t`): Pokazivač na Categories definisane u ovom binary-ju
- `__objc_nlclslist` (`classref_t`): Pokazivač na Non-Lazy Objective‑C klase definisane u ovom binary-ju
- `__objc_classlist` (`classref_t`): Pokazivači na sve Objective‑C klase definisane u ovom binary-ju

Takođe koristi nekoliko sekcija u segmentu `__TEXT` za čuvanje konstanti:

- `__objc_methname` (C‑String): Nazivi metoda
- `__objc_classname` (C‑String): Nazivi klasa
- `__objc_methtype` (C‑String): Tipovi metoda

Moderni macOS/iOS (posebno na Apple Silicon-u) takođe smeštaju Objective‑C/Swift metadata u:

- `__DATA_CONST`: Neizmenjivi Objective‑C metadata koji se mogu deliti između procesa kao podaci samo za čitanje (na primer, mnoge `__objc_*` liste sada se nalaze ovde).
- `__AUTH` / `__AUTH_CONST`: Segmenti koji sadrže pokazivače čija se autentičnost mora proveriti tokom učitavanja ili korišćenja na arm64e (Pointer Authentication). U njima ćete takođe videti `__auth_got` u `__AUTH_CONST`, umesto samo legacy `__la_symbol_ptr`/`__got`. Kada vršite instrumentaciju ili hooking, ne zaboravite da u modernim binary-jima uzmete u obzir i `__got` i `__auth_got` entries.

Za osnovne informacije o dyld pre-optimization-u (npr. selector uniquing-u i precomputaciji klasa/protokola), kao i o tome zašto su mnoge od ovih sekcija „already fixed up“ kada potiču iz shared cache-a, pogledajte Apple `objc-opt` izvore i beleške o dyld shared cache-u. Ovo utiče na to gde i kako možete patch-ovati metadata tokom runtime-a.

{{#ref}}
../macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.md
{{#endref}}

### Type Encoding

Objective‑C koristi mangling za kodiranje tipova selektora i promenljivih jednostavnih i složenih tipova:

- Primitivni tipovi koriste svoje prvo slovo: `i` za `int`, `c` za `char`, `l` za `long`... i koriste veliko slovo kada su unsigned (`L` za `unsigned long`).
- Ostali tipovi podataka koriste druga slova ili simbole, kao što su `q` za `long long`, `b` za bitfields, `B` za booleans, `#` za klase, `@` za `id`, `*` za `char *`, `^` za generičke pokazivače i `?` za nedefinisane tipove.
- Arrays, structures i unions koriste redom `[`, `{` i `(`.

#### Example Method Declaration
```objectivec
- (NSString *)processString:(id)input withOptions:(char *)options andError:(id)error;
```
Selector bi bio `processString:withOptions:andError:`

#### Kodiranje tipova

- `id` se kodira kao `@`
- `char *` se kodira kao `*`

Potpuno kodiranje tipova za metodu je:
```less
@24@0:8@16*20^@24
```
#### Detaljna analiza

1. Povratni tip (`NSString *`): Kodiran kao `@` sa dužinom 24
2. `self` (instanca objekta): Kodiran kao `@`, na pomeraju 0
3. `_cmd` (selector): Kodiran kao `:`, na pomeraju 8
4. Prvi argument (`char * input`): Kodiran kao `*`, na pomeraju 16
5. Drugi argument (`NSDictionary * options`): Kodiran kao `@`, na pomeraju 20
6. Treći argument (`NSError ** error`): Kodiran kao `^@`, na pomeraju 24

Pomoću selector-a i encoding-a možete rekonstruisati metodu.

### Klase

Klase u Objective‑C-u su C strukture sa svojstvima, pokazivačima na metode itd. Strukturu `objc_class` moguće je pronaći u [**izvornom kodu**](https://opensource.apple.com/source/objc4/objc4-756.2/runtime/objc-runtime-new.h.auto.html):
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
Ova klasa koristi neke delove polja `isa` za označavanje informacija o klasi.

Zatim struktura sadrži pokazivač na strukturu `class_ro_t`, sačuvanu na disku, koja sadrži atribute klase kao što su njen naziv, osnovne metode, properties i instance variables. Tokom izvršavanja koristi se dodatna struktura `class_rw_t`, koja sadrži pokazivače koji se mogu menjati, kao što su metode, protocols i properties.

{{#ref}}
../macos-basic-objective-c.md
{{#endref}}

---

## Moderne reprezentacije objekata u memoriji (arm64e, tagged pointers, Swift)

### Non-pointer `isa` i Pointer Authentication (arm64e)

Na Apple Silicon platformi i u novijim runtime okruženjima, Objective-C `isa` nije uvek sirovi pokazivač na klasu. Na arm64e platformi to je upakovana struktura koja može sadržati i Pointer Authentication Code (PAC). U zavisnosti od platforme, može uključivati polja kao što su `nonpointer`, `has_assoc`, `weakly_referenced`, `extra_rc` i sam pokazivač na klasu (pomeren ili potpisan). To znači da slepo dereferenciranje prvih 8 bajtova Objective-C objekta neće uvek dati validan `Class` pokazivač.<sup>[2]</sup>

Praktične napomene za debugging na arm64e:

- LLDB će obično ukloniti PAC bitove kada ispisuje Objective-C objekte pomoću `po`, ali pri radu sa sirovim pokazivačima možda ćete morati ručno da uklonite autentikaciju:

```lldb
(lldb) expr -l objc++ -- #include <ptrauth.h>
(lldb) expr -l objc++ -- void *raw = ptrauth_strip((void*)0x000000016f123abc, ptrauth_key_asda);
(lldb) expr -l objc++ -O -- (Class)object_getClass((id)raw)
```

- Mnogi function/data pointers u Mach-O datoteci nalaze se u `__AUTH`/`__AUTH_CONST` i zahtevaju autentikaciju pre upotrebe. Ako radite interposing ili re-binding (npr. u stilu fishhook-a), obavezno obradite i `__auth_got`, pored legacy `__got` sekcije.

Za detaljan pregled garancija jezika/ABI-ja i intrinsics dostupnih iz `<ptrauth.h>` u Clang/LLVM-u pogledajte referencu na kraju ove stranice.<sup>[1]</sup>

### Tagged pointer objekti

Neke Foundation klase izbegavaju heap allocation tako što payload objekta direktno kodiraju u vrednost pokazivača (tagged pointers). Detekcija se razlikuje u zavisnosti od platforme (npr. najznačajniji bit na arm64, a najmanje značajan na x86_64 macOS-u). Tagged objekti nemaju regularni `isa` sačuvan u memoriji; runtime određuje klasu na osnovu tag bitova.<sup>[2]</sup> Prilikom inspekcije proizvoljnih `id` vrednosti:

- Koristite runtime API-je umesto direktnog pristupanja polju `isa`: `object_getClass(obj)` / `[obj class]`.
- U LLDB-u će `po (id)0xADDR` ispravno ispisati tagged pointer instance, jer se runtime konsultuje radi određivanja klase.

### Swift heap objekti i metapodaci

Čiste Swift klase su takođe objekti sa header-om koji pokazuje na Swift metadata (a ne na Objective-C `isa`). Za introspekciju aktivnih Swift procesa bez njihovog menjanja možete koristiti Swift toolchain-ov `swift-inspect`, koji koristi Remote Mirror library za čitanje runtime metadata:
```bash
# Xcode toolchain (or Swift.org toolchain) provides swift-inspect
swift-inspect dump-raw-metadata <pid-or-name>
swift-inspect dump-arrays <pid-or-name>
# On Darwin additionally:
swift-inspect dump-concurrency <pid-or-name>
```
Ovo je veoma korisno za mapiranje Swift heap objekata i protocol conformances prilikom reverse engineering-a mešovitih Swift/ObjC aplikacija.

---

## Runtime inspection cheatsheet (LLDB / Frida)

### LLDB

- Ispiši objekat ili klasu iz raw pointer-a:
```lldb
(lldb) expr -l objc++ -O -- (id)0x0000000101234560
(lldb) expr -l objc++ -O -- (Class)object_getClass((id)0x0000000101234560)
```
- Ispitaj Objective-C klasu pomoću pokazivača na `self` metode objekta u breakpoint-u:
```lldb
(lldb) br se -n '-[NSFileManager fileExistsAtPath:]'
(lldb) r
... breakpoint hit ...
(lldb) po (id)$x0                 # self
(lldb) expr -l objc++ -O -- (Class)object_getClass((id)$x0)
```
- Dump sekcije koje sadrže Objective-C metadata (napomena: mnoge se sada nalaze u `__DATA_CONST` / `__AUTH_CONST`):
```lldb
(lldb) image dump section --section __DATA_CONST.__objc_classlist
(lldb) image dump section --section __DATA_CONST.__objc_selrefs
(lldb) image dump section --section __AUTH_CONST.__auth_got
```
- Pročitajte memoriju poznatog objekta klase da biste prešli na `class_ro_t` / `class_rw_t` prilikom reverse engineering-a lista metoda:
```lldb
(lldb) image lookup -r -n _OBJC_CLASS_$_NSFileManager
(lldb) memory read -fx -s8 0xADDRESS_OF_CLASS_OBJECT
```
### Frida (Objective-C i Swift)

Frida pruža high-level runtime bridges koji su veoma korisni za otkrivanje i instrumentaciju živih objekata bez symbols:

- Enumerate classes i methods, resolve stvarna imena klasa tokom runtime-a i intercept Objective-C selectors:
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
- Swift bridge: enumerate Swift tipove i interaguj sa Swift instancama (zahteva noviju verziju Frida; veoma korisno na Apple Silicon targetima).

---

## Reference

- [1] [Clang/LLVM: Pointer Authentication i ptrauth.h intrinsics (arm64e ABI)](https://clang.llvm.org/docs/PointerAuthentication.html)
- [2] [Apple objc runtime headers - objc-object.h (tagged pointers, non-pointer isa itd.)](https://opensource.apple.com/source/objc4/objc4-818.2/runtime/objc-object.h.auto.html)

{{#include ../../../banners/hacktricks-training.md}}
