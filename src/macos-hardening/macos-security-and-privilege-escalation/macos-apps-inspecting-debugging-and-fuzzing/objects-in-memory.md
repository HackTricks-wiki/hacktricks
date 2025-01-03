# Oggetti in memoria

{{#include ../../../banners/hacktricks-training.md}}

## CFRuntimeClass

Gli oggetti CF\* provengono da CoreFoundation, che fornisce più di 50 classi di oggetti come `CFString`, `CFNumber` o `CFAllocator`.

Tutte queste classi sono istanze della classe `CFRuntimeClass`, che quando chiamata restituisce un indice alla `__CFRuntimeClassTable`. La CFRuntimeClass è definita in [**CFRuntime.h**](https://opensource.apple.com/source/CF/CF-1153.18/CFRuntime.h.auto.html):
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

La maggior parte dei dati utilizzati dal runtime di ObjectiveC cambierà durante l'esecuzione, quindi utilizza alcune sezioni dal segmento **\_\_DATA** in memoria:

- **`__objc_msgrefs`** (`message_ref_t`): Riferimenti ai messaggi
- **`__objc_ivar`** (`ivar`): Variabili di istanza
- **`__objc_data`** (`...`): Dati mutabili
- **`__objc_classrefs`** (`Class`): Riferimenti alle classi
- **`__objc_superrefs`** (`Class`): Riferimenti alle superclassi
- **`__objc_protorefs`** (`protocol_t *`): Riferimenti ai protocolli
- **`__objc_selrefs`** (`SEL`): Riferimenti ai selettori
- **`__objc_const`** (`...`): Dati `r/o` della classe e altri dati (si spera) costanti
- **`__objc_imageinfo`** (`version, flags`): Utilizzato durante il caricamento dell'immagine: Versione attualmente `0`; I flag specificano il supporto GC preottimizzato, ecc.
- **`__objc_protolist`** (`protocol_t *`): Elenco dei protocolli
- **`__objc_nlcatlist`** (`category_t`): Puntatore a categorie non pigre definite in questo binario
- **`__objc_catlist`** (`category_t`): Puntatore a categorie definite in questo binario
- **`__objc_nlclslist`** (`classref_t`): Puntatore a classi Objective-C non pigre definite in questo binario
- **`__objc_classlist`** (`classref_t`): Puntatori a tutte le classi Objective-C definite in questo binario

Utilizza anche alcune sezioni nel segmento **`__TEXT`** per memorizzare valori costanti se non è possibile scrivere in questa sezione:

- **`__objc_methname`** (C-String): Nomi dei metodi
- **`__objc_classname`** (C-String): Nomi delle classi
- **`__objc_methtype`** (C-String): Tipi dei metodi

### Codifica dei tipi

Objective-C utilizza alcune mangling per codificare i selettori e i tipi di variabili di tipi semplici e complessi:

- I tipi primitivi usano la prima lettera del tipo `i` per `int`, `c` per `char`, `l` per `long`... e usano la lettera maiuscola nel caso sia senza segno (`L` per `unsigned Long`).
- Altri tipi di dati le cui lettere sono utilizzate o sono speciali, usano altre lettere o simboli come `q` per `long long`, `b` per `bitfields`, `B` per `booleans`, `#` per `classi`, `@` per `id`, `*` per `puntatori char`, `^` per `puntatori` generici e `?` per `indefiniti`.
- Array, strutture e unioni usano `[`, `{` e `(`

#### Dichiarazione del metodo di esempio
```objectivec
- (NSString *)processString:(id)input withOptions:(char *)options andError:(id)error;
```
Il selettore sarebbe `processString:withOptions:andError:`

#### Codifica del Tipo

- `id` è codificato come `@`
- `char *` è codificato come `*`

La codifica completa del tipo per il metodo è:
```less
@24@0:8@16*20^@24
```
#### Analisi Dettagliata

1. **Tipo di Ritorno (`NSString *`)**: Codificato come `@` con lunghezza 24
2. **`self` (istanza dell'oggetto)**: Codificato come `@`, a offset 0
3. **`_cmd` (selettore)**: Codificato come `:`, a offset 8
4. **Primo argomento (`char * input`)**: Codificato come `*`, a offset 16
5. **Secondo argomento (`NSDictionary * options`)**: Codificato come `@`, a offset 20
6. **Terzo argomento (`NSError ** error`)**: Codificato come `^@`, a offset 24

**Con il selettore + la codifica puoi ricostruire il metodo.**

### **Classi**

Le classi in Objective-C sono una struct con proprietà, puntatori ai metodi... È possibile trovare la struct `objc_class` nel [**codice sorgente**](https://opensource.apple.com/source/objc4/objc4-756.2/runtime/objc-runtime-new.h.auto.html):
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
Questa classe utilizza alcuni bit del campo isa per indicare alcune informazioni sulla classe.

Poi, la struct ha un puntatore alla struct `class_ro_t` memorizzata su disco che contiene attributi della classe come il suo nome, metodi di base, proprietà e variabili di istanza.\
Durante l'esecuzione, viene utilizzata una struttura aggiuntiva `class_rw_t` che contiene puntatori che possono essere modificati come metodi, protocolli, proprietà...

{{#include ../../../banners/hacktricks-training.md}}
