# Objekti u memoriji

{{#include ../../../banners/hacktricks-training.md}}

## CFRuntimeClass

CF* objekti potiču iz CoreFoundation-a, koji pruža više od 50 klasa objekata, kao što su `CFString`, `CFNumber` ili `CFAllocator`.

Sve ove klase su instance klase `CFRuntimeClass`, koja, kada se pozove, vraća indeks u `__CFRuntimeClassTable`. CFRuntimeClass je definisana u [**CFRuntime.h**](https://opensource.apple.com/source/CF/CF-1153.18/CFRuntime.h.auto.html):
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

### Korišćene sekcije memorije

Većina podataka koje koristi Objective‑C runtime menja se tokom izvršavanja, pa zato u memoriji koristi više sekcija iz Mach‑O familije segmenata `__DATA`. Istorijski su one obuhvatale:

- `__objc_msgrefs` (`message_ref_t`): Reference na poruke
- `__objc_ivar` (`ivar`): Promenljive instance
- `__objc_data` (`...`): Promenljivi podaci
- `__objc_classrefs` (`Class`): Reference na klase
- `__objc_superrefs` (`Class`): Reference na nadklase
- `__objc_protorefs` (`protocol_t *`): Reference na protokole
- `__objc_selrefs` (`SEL`): Reference na selektore
- `__objc_const` (`...`): Class r/o podaci i drugi (nadamo se) konstantni podaci
- `__objc_imageinfo` (`version, flags`): Koristi se tokom učitavanja image-a: Trenutna verzija je `0`; Flags određuju podršku za preoptimizovani GC itd.
- `__objc_protolist` (`protocol_t *`): Lista protokola
- `__objc_nlcatlist` (`category_t`): Pokazivač na Non-Lazy Categories definisane u ovom binary-ju
- `__objc_catlist` (`category_t`): Pokazivač na Categories definisane u ovom binary-ju
- `__objc_nlclslist` (`classref_t`): Pokazivač na Non-Lazy Objective‑C klase definisane u ovom binary-ju
- `__objc_classlist` (`classref_t`): Pokazivači na sve Objective‑C klase definisane u ovom binary-ju

Takođe koristi nekoliko sekcija u segmentu `__TEXT` za čuvanje konstanti:

- `__objc_methname` (C‑String): Imena metoda
- `__objc_classname` (C‑String): Imena klasa
- `__objc_methtype` (C‑String): Tipovi metoda

Moderni macOS/iOS (posebno na Apple Silicon-u) takođe smešta Objective‑C/Swift metadata u:

- `__DATA_CONST`: nepromenljivi Objective‑C metadata koji se može deliti između procesa u režimu read-only (na primer, mnoge `__objc_*` liste se sada nalaze ovde).
- `__AUTH` / `__AUTH_CONST`: segmenti koji sadrže pokazivače koji moraju biti autentifikovani prilikom učitavanja ili korišćenja na arm64e (Pointer Authentication). Takođe ćete u `__AUTH_CONST` umesto legacy `__la_symbol_ptr`/`__got` često videti samo `__auth_got`. Kada instrumentirate ili radite hooking, imajte u vidu i `__got` i `__auth_got` unose u modernim binary-jima.

Za pozadinu o dyld pre-optimizaciji (npr. selector uniquing i precomputing klasa/protokola) i o tome zašto su mnoge od ovih sekcija „već fixup-ovane“ kada dolaze iz shared cache-a, pogledajte Apple `objc-opt` izvorni kod i beleške o dyld shared cache-u. Ovo utiče na to gde i kako možete patch-ovati metadata tokom runtime-a.

{{#ref}}
../macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.md
{{#endref}}

### Kodiranje tipova

Objective‑C koristi mangling za kodiranje tipova selektora i promenljivih jednostavnih i složenih tipova:

- Primitivni tipovi koriste prvo slovo tipa `i` za `int`, `c` za `char`, `l` za `long`... i koriste veliko slovo kada je tip unsigned (`L` za `unsigned long`).
- Drugi tipovi podataka koriste druga slova ili simbole, kao što su `q` za `long long`, `b` za bitfields, `B` za booleans, `#` za klase, `@` za `id`, `*` za `char *`, `^` za generičke pokazivače i `?` za nedefinisane tipove.
- Nizovi, strukture i unije koriste redom `[`, `{` i `(`.

#### Primer deklaracije metode
```objectivec
- (NSString *)processString:(id)input withOptions:(char *)options andError:(id)error;
```
Selector bi bio `processString:withOptions:andError:`

#### Kodiranje tipova

- `id` se kodira kao `@`
- `char *` se kodira kao `*`

Potpuno kodiranje tipova za ovu metodu je:
```less
@24@0:8@16*20^@24
```
#### Detaljna analiza

1. Povratni tip (`NSString *`): kodiran kao `@`, dužine 24
2. `self` (instanca objekta): kodiran kao `@`, na pomeraju 0
3. `_cmd` (selektor): kodiran kao `:`, na pomeraju 8
4. Prvi argument (`char * input`): kodiran kao `*`, na pomeraju 16
5. Drugi argument (`NSDictionary * options`): kodiran kao `@`, na pomeraju 20
6. Treći argument (`NSError ** error`): kodiran kao `^@`, na pomeraju 24

Pomoću selektora i kodiranja možete rekonstruisati metodu.

### Klase

Klase u Objective‑C su C strukture sa svojstvima, pokazivačima na metode itd. Strukturu `objc_class` moguće je pronaći u [**izvornom kodu**](https://opensource.apple.com/source/objc4/objc4-756.2/runtime/objc-runtime-new.h.auto.html):
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
Ova klasa koristi neke bitove polja `isa` za označavanje informacija o klasi.

Zatim, struktura sadrži pokazivač na strukturu `class_ro_t`, uskladištenu na disku, koja sadrži atribute klase kao što su njeno ime, osnovne metode, properties i instance variables. Tokom izvršavanja koristi se dodatna struktura `class_rw_t`, koja sadrži pokazivače koji se mogu menjati, kao što su metode, protokoli i properties.

{{#ref}}
../macos-basic-objective-c.md
{{#endref}}

---

## Moderne reprezentacije objekata u memoriji (arm64e, tagged pointers, Swift)

### Non-pointer `isa` i Pointer Authentication (arm64e)

Na Apple Silicon platformama i u novijim runtime okruženjima, Objective-C `isa` nije uvek sirov pokazivač na klasu. Na arm64e platformi to je upakovana struktura koja može sadržati i Pointer Authentication Code (PAC). U zavisnosti od platforme, može sadržati polja kao što su `nonpointer`, `has_assoc`, `weakly_referenced`, `extra_rc`, kao i sam pokazivač na klasu (pomeren ili potpisan). To znači da slepo dereferenciranje prvih 8 bajtova Objective-C objekta neće uvek dati validan `Class` pokazivač.<sup>[[2]](#references)</sup>

Praktične napomene za debugging na arm64e:

- LLDB će obično ukloniti PAC bitove umesto vas prilikom ispisivanja Objective-C objekata pomoću `po`, ali pri radu sa sirovim pokazivačima možda ćete morati ručno da uklonite authentication:

```lldb
(lldb) expr -l objc++ -- #include <ptrauth.h>
(lldb) expr -l objc++ -- void *raw = ptrauth_strip((void*)0x000000016f123abc, ptrauth_key_asda);
(lldb) expr -l objc++ -O -- (Class)object_getClass((id)raw)
```

- Mnogi pokazivači na funkcije/podatke u Mach-O datotekama nalaze se u `__AUTH`/`__AUTH_CONST` i zahtevaju authentication pre upotrebe. Ako radite interposing ili re-binding (npr. u fishhook stilu), obavezno obradite i `__auth_got`, pored legacy `__got`.

Za detaljan pregled jezičkih/ABI garancija i intrinsics dostupnih u `<ptrauth.h>` iz Clang/LLVM alata, pogledajte referencu na kraju ove stranice.<sup>[[1]](#references)</sup>

### Tagged pointer objekti

Neke Foundation klase izbegavaju heap alokaciju tako što payload objekta direktno kodiraju u vrednost pokazivača (tagged pointers). Detekcija se razlikuje u zavisnosti od platforme (npr. najznačajniji bit na arm64, a najmanje značajan na x86_64 macOS). Tagged objekti nemaju uobičajeni `isa` uskladišten u memoriji; runtime određuje klasu na osnovu tag bitova.<sup>[[2]](#references)</sup> Prilikom inspekcije proizvoljnih `id` vrednosti:

- Koristite runtime API-je umesto direktnog pristupanja polju `isa`: `object_getClass(obj)` / `[obj class]`.
- U LLDB-u će `po (id)0xADDR` ispravno ispisati tagged pointer instance, jer se runtime koristi za određivanje klase.

### Swift heap objekti i metadata

Čiste Swift klase su takođe objekti sa zaglavljem koje pokazuje na Swift metadata (a ne na Objective-C `isa`). Za introspekciju aktivnih Swift procesa bez njihovog menjanja možete koristiti `swift-inspect` iz Swift toolchain-a, koji koristi Remote Mirror biblioteku za čitanje runtime metadata:
```bash
# Xcode toolchain (or Swift.org toolchain) provides swift-inspect
swift-inspect dump-raw-metadata <pid-or-name>
swift-inspect dump-arrays <pid-or-name>
# On Darwin additionally:
swift-inspect dump-concurrency <pid-or-name>
```
Ovo je veoma korisno za mapiranje Swift heap objekata i usklađenosti sa protokolima prilikom reverse engineering-a mešovitih Swift/ObjC aplikacija.

---

## Cheatsheet za runtime inspekciju (LLDB / Frida)

### LLDB

- Ispiši objekat ili klasu iz raw pokazivača:
```lldb
(lldb) expr -l objc++ -O -- (id)0x0000000101234560
(lldb) expr -l objc++ -O -- (Class)object_getClass((id)0x0000000101234560)
```
- Ispitaj Objective-C klasu iz pokazivača na `self` metode objekta u breakpoint-u:
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
- Pročitajte memoriju za poznati objekat klase da biste prešli na `class_ro_t` / `class_rw_t` prilikom reverseovanja lista metoda:
```lldb
(lldb) image lookup -r -n _OBJC_CLASS_$_NSFileManager
(lldb) memory read -fx -s8 0xADDRESS_OF_CLASS_OBJECT
```
### Frida (Objective‑C i Swift)

Frida pruža high-level runtime bridge-ove koji su veoma korisni za otkrivanje i instrumentaciju živih objekata bez simbola:

- Enumerišite klase i metode, razrešite stvarna imena klasa tokom runtime-a i presrećite Objective‑C selektore:
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
- Swift bridge: enumerate Swift types and interact with Swift instances (zahteva noviji Frida; veoma korisno na Apple Silicon targets).

---

## Reference

- [1] [Clang/LLVM: Pointer Authentication and the ptrauth.h intrinsics (arm64e ABI)](https://clang.llvm.org/docs/PointerAuthentication.html)
- [2] [Apple objc runtime headers - objc-object.h (tagged pointers, non‑pointer isa, etc.)](https://opensource.apple.com/source/objc4/objc4-818.2/runtime/objc-object.h.auto.html)

{{#include ../../../banners/hacktricks-training.md}}
