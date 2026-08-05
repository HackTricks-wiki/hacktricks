# Oggetti in memoria

{{#include ../../../banners/hacktricks-training.md}}

## CFRuntimeClass

Gli oggetti CF* provengono da CoreFoundation, che fornisce più di 50 classi di oggetti come `CFString`, `CFNumber` o `CFAllocator`.

Tutte queste classi sono istanze della classe `CFRuntimeClass`, che, quando viene chiamata, restituisce un indice nella `__CFRuntimeClassTable`. La CFRuntimeClass è definita in [**CFRuntime.h**](https://opensource.apple.com/source/CF/CF-1153.18/CFRuntime.h.auto.html):
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

### Sezioni di memoria utilizzate

La maggior parte dei dati utilizzati dal runtime di Objective‑C cambierà durante l'esecuzione; pertanto, utilizza diverse sezioni della famiglia di segmenti Mach‑O `__DATA` in memoria. Storicamente includevano:

- `__objc_msgrefs` (`message_ref_t`): Riferimenti ai messaggi
- `__objc_ivar` (`ivar`): Variabili di istanza
- `__objc_data` (`...`): Dati mutabili
- `__objc_classrefs` (`Class`): Riferimenti alle classi
- `__objc_superrefs` (`Class`): Riferimenti alle superclassi
- `__objc_protorefs` (`protocol_t *`): Riferimenti ai protocolli
- `__objc_selrefs` (`SEL`): Riferimenti ai selector
- `__objc_const` (`...`): Dati r/o delle classi e altri dati (si spera) costanti
- `__objc_imageinfo` (`version, flags`): Utilizzata durante il caricamento dell'immagine: la versione è attualmente `0`; i flag specificano il supporto al GC preottimizzato, ecc.
- `__objc_protolist` (`protocol_t *`): Elenco dei protocolli
- `__objc_nlcatlist` (`category_t`): Puntatore alle Non-Lazy Categories definite in questo binario
- `__objc_catlist` (`category_t`): Puntatore alle Categories definite in questo binario
- `__objc_nlclslist` (`classref_t`): Puntatore alle classi Objective‑C Non-Lazy definite in questo binario
- `__objc_classlist` (`classref_t`): Puntatori a tutte le classi Objective‑C definite in questo binario

Utilizza inoltre alcune sezioni nel segmento `__TEXT` per memorizzare costanti:

- `__objc_methname` (C‑String): Nomi dei metodi
- `__objc_classname` (C‑String): Nomi delle classi
- `__objc_methtype` (C‑String): Tipi dei metodi

Le versioni moderne di macOS/iOS (specialmente su Apple Silicon) collocano inoltre i metadata di Objective‑C/Swift in:

- `__DATA_CONST`: metadata Objective‑C immutabili che possono essere condivisi in sola lettura tra i processi (ad esempio, molti elenchi `__objc_*` ora si trovano qui).
- `__AUTH` / `__AUTH_CONST`: segmenti contenenti puntatori che devono essere autenticati al caricamento o al momento dell'utilizzo su arm64e (Pointer Authentication). In `__AUTH_CONST` si vedrà anche `__auth_got`, invece delle sole sezioni legacy `__la_symbol_ptr`/`__got`. Quando si strumenta o si esegue hooking, è necessario tenere conto sia delle entry `__got` sia di quelle `__auth_got nei binari moderni.

Per informazioni di base sulla pre-ottimizzazione di dyld (ad esempio, l'unificazione dei selector e il precalcolo di classi/protocolli) e sul motivo per cui molte di queste sezioni sono "già corrette" quando provengono dalla shared cache, consultare i sorgenti Apple `objc-opt` e le note sulla dyld shared cache. Questo influisce su dove e come è possibile patchare i metadata a runtime.

{{#ref}}
../macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.md
{{#endref}}

### Codifica dei tipi

Objective‑C utilizza il mangling per codificare i tipi di selector e variabili, sia semplici sia complessi:

- I tipi primitivi utilizzano la prima lettera del tipo: `i` per `int`, `c` per `char`, `l` per `long`... e utilizzano la lettera maiuscola quando il tipo è unsigned (`L` per `unsigned long`).
- Gli altri tipi di dati utilizzano altre lettere o simboli, come `q` per `long long`, `b` per i bitfield, `B` per i booleani, `#` per le classi, `@` per `id`, `*` per `char *`, `^` per i puntatori generici e `?` per i tipi non definiti.
- Array, strutture e union utilizzano rispettivamente `[`, `{` e `(`.

#### Esempio di dichiarazione di un metodo
```objectivec
- (NSString *)processString:(id)input withOptions:(char *)options andError:(id)error;
```
Il selector sarebbe `processString:withOptions:andError:`

#### Codifica dei tipi

- `id` viene codificato come `@`
- `char *` viene codificato come `*`

La codifica completa dei tipi per il metodo è:
```less
@24@0:8@16*20^@24
```
#### Analisi dettagliata

1. Tipo restituito (`NSString *`): codificato come `@` con lunghezza 24
2. `self` (istanza dell'oggetto): codificato come `@`, all'offset 0
3. `_cmd` (selector): codificato come `:`, all'offset 8
4. Primo argomento (`char * input`): codificato come `*`, all'offset 16
5. Secondo argomento (`NSDictionary * options`): codificato come `@`, all'offset 20
6. Terzo argomento (`NSError ** error`): codificato come `^@`, all'offset 24

Con il selector e l'encoding è possibile ricostruire il metodo.

### Classi

Le classi in Objective-C sono strutture C con proprietà, puntatori ai metodi, ecc. È possibile trovare la struct `objc_class` nel [**codice sorgente**](https://opensource.apple.com/source/objc4/objc4-756.2/runtime/objc-runtime-new.h.auto.html):
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
Questa classe utilizza alcuni bit del campo `isa` per indicare informazioni sulla classe.

Quindi, la struct ha un puntatore alla struct `class_ro_t` memorizzata su disco, che contiene attributi della classe come il suo nome, i metodi base, le properties e le instance variables. Durante il runtime viene utilizzata un'ulteriore struttura, `class_rw_t`, contenente puntatori che possono essere modificati, come metodi, protocolli e properties.

{{#ref}}
../macos-basic-objective-c.md
{{#endref}}

---

## Rappresentazioni moderne degli oggetti in memoria (arm64e, tagged pointers, Swift)

### `isa` non-pointer e Pointer Authentication (arm64e)

Sui dispositivi Apple Silicon e nei runtime recenti, l'`isa` di Objective-C non è sempre un raw class pointer. Su arm64e è una packed structure che può contenere anche un Pointer Authentication Code (PAC). A seconda della piattaforma, può includere campi come `nonpointer`, `has_assoc`, `weakly_referenced`, `extra_rc` e il class pointer stesso (shifted o signed). Questo significa che il dereferencing alla cieca dei primi 8 byte di un oggetto Objective-C non restituisce sempre un `Class` pointer valido.<sup>[2]</sup>

Note pratiche durante il debugging su arm64e:

- LLDB di solito rimuove per te i bit PAC quando stampa oggetti Objective-C con `po`, ma quando lavori con raw pointers potresti dover rimuovere manualmente l'autenticazione:

```lldb
(lldb) expr -l objc++ -- #include <ptrauth.h>
(lldb) expr -l objc++ -- void *raw = ptrauth_strip((void*)0x000000016f123abc, ptrauth_key_asda);
(lldb) expr -l objc++ -O -- (Class)object_getClass((id)raw)
```

- Molti function/data pointers in Mach-O risiedono in `__AUTH`/`__AUTH_CONST` e richiedono l'autenticazione prima dell'uso. Se stai facendo interposing o re-binding (ad esempio in stile fishhook), assicurati di gestire anche `__auth_got`, oltre al legacy `__got`.

Per un'analisi approfondita delle garanzie del linguaggio/ABI e degli intrinsic `<ptrauth.h>` disponibili da Clang/LLVM, consulta il riferimento alla fine di questa pagina.<sup>[1]</sup>

### Tagged pointer objects

Alcune classi Foundation evitano l'heap allocation codificando il payload dell'oggetto direttamente nel pointer value (tagged pointers). Il rilevamento varia a seconda della piattaforma (ad esempio, il bit più significativo su arm64 e quello meno significativo su macOS x86_64). Gli oggetti tagged non hanno un `isa` regolare memorizzato in memoria; il runtime risolve la classe dai tag bits.<sup>[2]</sup> Quando ispezioni valori `id` arbitrari:

- Utilizza le runtime API invece di accedere direttamente al campo `isa`: `object_getClass(obj)` / `[obj class]`.
- In LLDB, `po (id)0xADDR` stamperà correttamente le istanze tagged pointer, perché il runtime viene consultato per risolvere la classe.

### Swift heap objects e metadata

Le pure Swift classes sono anch'esse oggetti con un header che punta ai metadata Swift, non a un'`isa` Objective-C. Per effettuare introspection su processi Swift attivi senza modificarli, puoi utilizzare `swift-inspect` della Swift toolchain, che sfrutta la Remote Mirror library per leggere i runtime metadata:
```bash
# Xcode toolchain (or Swift.org toolchain) provides swift-inspect
swift-inspect dump-raw-metadata <pid-or-name>
swift-inspect dump-arrays <pid-or-name>
# On Darwin additionally:
swift-inspect dump-concurrency <pid-or-name>
```
Questo è molto utile per mappare gli oggetti nell'heap di Swift e le conformità ai protocolli durante il reverse engineering di app miste Swift/ObjC.

---

## Cheatsheet per l'ispezione del runtime (LLDB / Frida)

### LLDB

- Stampare l'oggetto o la classe da un puntatore raw:
```lldb
(lldb) expr -l objc++ -O -- (id)0x0000000101234560
(lldb) expr -l objc++ -O -- (Class)object_getClass((id)0x0000000101234560)
```
- Ispeziona la classe Objective-C da un puntatore a `self` del metodo di un oggetto in un breakpoint:
```lldb
(lldb) br se -n '-[NSFileManager fileExistsAtPath:]'
(lldb) r
... breakpoint hit ...
(lldb) po (id)$x0                 # self
(lldb) expr -l objc++ -O -- (Class)object_getClass((id)$x0)
```
- Dump delle sezioni che contengono metadati Objective-C (nota: molte si trovano ora in `__DATA_CONST` / `__AUTH_CONST`):
```lldb
(lldb) image dump section --section __DATA_CONST.__objc_classlist
(lldb) image dump section --section __DATA_CONST.__objc_selrefs
(lldb) image dump section --section __AUTH_CONST.__auth_got
```
- Leggi la memoria di un oggetto di una classe nota per eseguire il pivot verso `class_ro_t` / `class_rw_t` durante il reversing delle liste dei metodi:
```lldb
(lldb) image lookup -r -n _OBJC_CLASS_$_NSFileManager
(lldb) memory read -fx -s8 0xADDRESS_OF_CLASS_OBJECT
```
### Frida (Objective‑C e Swift)

Frida fornisce bridge runtime di alto livello, molto utili per individuare e strumentare oggetti attivi senza simboli:

- Enumerare classi e metodi, risolvere i nomi effettivi delle classi a runtime e intercettare i selector Objective-C:
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
- Swift bridge: enumerare i tipi Swift e interagire con le istanze Swift (richiede una versione recente di Frida; molto utile sui target Apple Silicon).

---

## Riferimenti

- [1] [Clang/LLVM: Pointer Authentication e gli intrinsic ptrauth.h (ABI arm64e)](https://clang.llvm.org/docs/PointerAuthentication.html)
- [2] [Header del runtime objc di Apple - objc-object.h (tagged pointers, isa non-pointer, ecc.)](https://opensource.apple.com/source/objc4/objc4-818.2/runtime/objc-object.h.auto.html)

{{#include ../../../banners/hacktricks-training.md}}
