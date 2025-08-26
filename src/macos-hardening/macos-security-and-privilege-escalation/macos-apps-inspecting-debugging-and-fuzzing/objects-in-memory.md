# Oggetti in memoria

{{#include ../../../banners/hacktricks-training.md}}

## CFRuntimeClass

Gli oggetti CF* provengono da CoreFoundation, che fornisce oltre 50 classi di oggetti come `CFString`, `CFNumber` o `CFAllocator`.

Tutte queste classi sono istanze della classe `CFRuntimeClass`, che quando invocata restituisce un indice alla `__CFRuntimeClassTable`. La CFRuntimeClass è definita in [**CFRuntime.h**](https://opensource.apple.com/source/CF/CF-1153.18/CFRuntime.h.auto.html):
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

La maggior parte dei dati usati dal runtime Objective‑C cambia durante l'esecuzione, quindi utilizza diverse sezioni del Mach‑O nella famiglia di segmenti `__DATA` in memoria. Storicamente queste includevano:

- `__objc_msgrefs` (`message_ref_t`): Riferimenti ai messaggi
- `__objc_ivar` (`ivar`): Variabili di istanza
- `__objc_data` (`...`): Dati mutabili
- `__objc_classrefs` (`Class`): Riferimenti a classi
- `__objc_superrefs` (`Class`): Riferimenti a superclassi
- `__objc_protorefs` (`protocol_t *`): Riferimenti a protocolli
- `__objc_selrefs` (`SEL`): Riferimenti a selector
- `__objc_const` (`...`): Dati di sola lettura delle classi e altri dati (si spera) costanti
- `__objc_imageinfo` (`version, flags`): Usato durante il caricamento dell'immagine: Versione attuale `0`; Flags specificano supporto GC preottimizzato, ecc.
- `__objc_protolist` (`protocol_t *`): Lista di protocolli
- `__objc_nlcatlist` (`category_t`): Puntatore alle Non-Lazy Categories definite in questo binario
- `__objc_catlist` (`category_t`): Puntatore alle Categories definite in questo binario
- `__objc_nlclslist` (`classref_t`): Puntatore alle classi Objective‑C Non-Lazy definite in questo binario
- `__objc_classlist` (`classref_t`): Puntatori a tutte le classi Objective‑C definite in questo binario

Usa inoltre alcune sezioni nel segmento `__TEXT` per memorizzare costanti:

- `__objc_methname` (C‑String): Nomi dei metodi
- `__objc_classname` (C‑String): Nomi delle classi
- `__objc_methtype` (C‑String): Tipi dei metodi

Le versioni moderne di macOS/iOS (soprattutto su Apple Silicon) collocano inoltre metadata Objective‑C/Swift in:

- `__DATA_CONST`: metadata Objective‑C immutabile che può essere condiviso come sola lettura tra processi (per esempio molte liste `__objc_*` ora risiedono qui).
- `__AUTH` / `__AUTH_CONST`: segmenti contenenti puntatori che devono essere autenticati al momento del caricamento o dell'uso su arm64e (Pointer Authentication). Vedrai anche `__auth_got` in `__AUTH_CONST` invece del legacy `__la_symbol_ptr`/`__got` solamente. Quando strumentalizzi o fai hooking, ricorda di considerare sia le voci `__got` sia `__auth_got` nei binari moderni.

Per il background su dyld pre‑optimization (es. selector uniquing e class/protocol precomputation) e sul perché molte di queste sezioni sono "già sistemate" quando provengono dallo shared cache, consulta le sorgenti Apple `objc-opt` e le note sul dyld shared cache. Questo influisce su dove e come puoi patchare i metadata a runtime.

{{#ref}}
../macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.md
{{#endref}}

### Type Encoding

Objective‑C usa il mangling per codificare selector e tipi di variabili semplici e complessi:

- I tipi primitivi usano la prima lettera del tipo `i` per `int`, `c` per `char`, `l` per `long`... e usano la lettera maiuscola nel caso sia unsigned (`L` per `unsigned long`).
- Altri tipi di dato usano altre lettere o simboli come `q` per `long long`, `b` per bitfield, `B` per booleani, `#` per classi, `@` per `id`, `*` per `char *`, `^` per puntatori generici e `?` per indefinito.
- Array, struct e union usano rispettivamente `[`, `{` e `(`.

#### Esempio di dichiarazione di metodo
```objectivec
- (NSString *)processString:(id)input withOptions:(char *)options andError:(id)error;
```
Il selector sarebbe `processString:withOptions:andError:`

#### Codifica dei tipi

- `id` è codificato come `@`
- `char *` è codificato come `*`

La codifica completa dei tipi per il metodo è:
```less
@24@0:8@16*20^@24
```
#### Analisi dettagliata

1. Tipo di ritorno (`NSString *`): Codificato come `@` con lunghezza 24
2. `self` (istanza dell'oggetto): Codificato come `@`, all'offset 0
3. `_cmd` (selector): Codificato come `:`, all'offset 8
4. Primo argomento (`char * input`): Codificato come `*`, all'offset 16
5. Secondo argomento (`NSDictionary * options`): Codificato come `@`, all'offset 20
6. Terzo argomento (`NSError ** error`): Codificato come `^@`, all'offset 24

Con il selector + la codifica puoi ricostruire il metodo.

### Classi

Le classi in Objective‑C sono struct C con proprietà, puntatori a metodi, ecc. È possibile trovare la struct `objc_class` nel [**source code**](https://opensource.apple.com/source/objc4/objc4-756.2/runtime/objc-runtime-new.h.auto.html):
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
Questa classe usa alcuni bit del campo `isa` per indicare informazioni sulla classe.

Poi, la struct ha un puntatore alla struct `class_ro_t` memorizzata su disco che contiene attributi della classe come il suo nome, i metodi base, le proprietà e le variabili d'istanza. Durante l'esecuzione viene usata una struttura aggiuntiva `class_rw_t` contenente puntatori che possono essere modificati, come metodi, protocolli e proprietà.

{{#ref}}
../macos-basic-objective-c.md
{{#endref}}

---

## Rappresentazioni moderne degli oggetti in memoria (arm64e, tagged pointers, Swift)

### Non‑pointer `isa` and Pointer Authentication (arm64e)

Su Apple Silicon e nei runtime recenti l'`isa` di Objective‑C non è sempre un semplice puntatore a classe. Su arm64e è una struttura impacchettata che può anche contenere un Pointer Authentication Code (PAC). A seconda della piattaforma può includere campi come `nonpointer`, `has_assoc`, `weakly_referenced`, `extra_rc`, e il puntatore alla classe stesso (shifted o signed). Questo significa che dereferenziare ciecamente i primi 8 byte di un oggetto Objective‑C non restituirà sempre un puntatore `Class` valido.

Note pratiche quando si effettua il debugging su arm64e:

- LLDB solitamente rimuove i bit PAC per te quando stampa oggetti Objective‑C con `po`, ma quando lavori con puntatori raw potresti dover rimuovere manualmente l'autenticazione:

```lldb
(lldb) expr -l objc++ -- #include <ptrauth.h>
(lldb) expr -l objc++ -- void *raw = ptrauth_strip((void*)0x000000016f123abc, ptrauth_key_asda);
(lldb) expr -l objc++ -O -- (Class)object_getClass((id)raw)
```

- Molti puntatori a funzioni/dati in Mach‑O risiederanno in `__AUTH`/`__AUTH_CONST` e richiederanno autenticazione prima dell'uso. Se stai interponendo o ri‑binding (ad es., in stile fishhook), assicurati di gestire anche `__auth_got` oltre al classico `__got`.

Per un'analisi approfondita delle garanzie del linguaggio/ABI e degli intrinseci `<ptrauth.h>` disponibili da Clang/LLVM, vedi la referenza alla fine di questa pagina.

### Tagged pointer objects

Alcune classi di Foundation evitano l'allocazione sull'heap codificando il payload dell'oggetto direttamente nel valore del puntatore (tagged pointers). La rilevazione varia a seconda della piattaforma (es., il bit più significativo su arm64, il meno significativo su macOS x86_64). Gli oggetti tagged non hanno un `isa` regolare memorizzato in memoria; il runtime risolve la classe a partire dai bit del tag. Quando si ispezionano valori `id` arbitrari:

- Usa le API del runtime invece di accedere direttamente al campo `isa`: `object_getClass(obj)` / `[obj class]`.
- In LLDB, semplicemente `po (id)0xADDR` stamperà correttamente le istanze tagged pointer perché il runtime viene consultato per risolvere la classe.

### Swift heap objects and metadata

Le classi Swift pure sono anch'esse oggetti con un header che punta ai metadati Swift (non all'`isa` di Objective‑C). Per ispezionare processi Swift attivi senza modificarli puoi usare `swift-inspect` della toolchain Swift, che sfrutta la libreria Remote Mirror per leggere i metadati del runtime:
```bash
# Xcode toolchain (or Swift.org toolchain) provides swift-inspect
swift-inspect dump-raw-metadata <pid-or-name>
swift-inspect dump-arrays <pid-or-name>
# On Darwin additionally:
swift-inspect dump-concurrency <pid-or-name>
```
Questo è molto utile per mappare gli oggetti nello heap di Swift e le conformità ai protocolli quando si esegue reverse engineering di app miste Swift/ObjC.

---

## Cheatsheet per l'ispezione del runtime (LLDB / Frida)

### LLDB

- Stampare un oggetto o una classe da un puntatore raw:
```lldb
(lldb) expr -l objc++ -O -- (id)0x0000000101234560
(lldb) expr -l objc++ -O -- (Class)object_getClass((id)0x0000000101234560)
```
- Ispeziona la classe Objective‑C a partire da un puntatore a `self` di un metodo di un oggetto in un breakpoint:
```lldb
(lldb) br se -n '-[NSFileManager fileExistsAtPath:]'
(lldb) r
... breakpoint hit ...
(lldb) po (id)$x0                 # self
(lldb) expr -l objc++ -O -- (Class)object_getClass((id)$x0)
```
- Dump sezioni che contengono i metadati di Objective‑C (nota: molte ora si trovano in `__DATA_CONST` / `__AUTH_CONST`):
```lldb
(lldb) image dump section --section __DATA_CONST.__objc_classlist
(lldb) image dump section --section __DATA_CONST.__objc_selrefs
(lldb) image dump section --section __AUTH_CONST.__auth_got
```
- Leggi la memoria di un oggetto di classe noto per pivot to `class_ro_t` / `class_rw_t` when reversing method lists:
```lldb
(lldb) image lookup -r -n _OBJC_CLASS_$_NSFileManager
(lldb) memory read -fx -s8 0xADDRESS_OF_CLASS_OBJECT
```
### Frida (Objective‑C and Swift)

Frida fornisce bridge di runtime di alto livello molto utili per scoprire e strumentare oggetti live senza simboli:

- Enumerare classi e metodi, risolvere i nomi reali delle classi a runtime e intercettare Objective‑C selectors:
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
- Swift bridge: enumerare i tipi Swift e interagire con le istanze Swift (richiede Frida recente; molto utile sui target Apple Silicon).

---

## Riferimenti

- Clang/LLVM: Pointer Authentication e le `<ptrauth.h>` intrinsics (arm64e ABI). https://clang.llvm.org/docs/PointerAuthentication.html
- Apple objc runtime headers (tagged pointers, non‑pointer `isa`, etc.) e.g., `objc-object.h`. https://opensource.apple.com/source/objc4/objc4-818.2/runtime/objc-object.h.auto.html

{{#include ../../../banners/hacktricks-training.md}}
