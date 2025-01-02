# Objekte im Speicher

{{#include ../../../banners/hacktricks-training.md}}

## CFRuntimeClass

CF\* Objekte stammen aus CoreFoundation, das mehr als 50 Klassen von Objekten wie `CFString`, `CFNumber` oder `CFAllocator` bereitstellt.

Alle diese Klassen sind Instanzen der Klasse `CFRuntimeClass`, die, wenn sie aufgerufen wird, einen Index zur `__CFRuntimeClassTable` zurückgibt. Die CFRuntimeClass ist in [**CFRuntime.h**](https://opensource.apple.com/source/CF/CF-1153.18/CFRuntime.h.auto.html) definiert:
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

### Verwendete Speicherabschnitte

Die meisten Daten, die von der ObjectiveC-Laufzeit verwendet werden, ändern sich während der Ausführung, daher verwendet es einige Abschnitte aus dem **\_\_DATA**-Segment im Speicher:

- **`__objc_msgrefs`** (`message_ref_t`): Nachrichtenreferenzen
- **`__objc_ivar`** (`ivar`): Instanzvariablen
- **`__objc_data`** (`...`): Änderbare Daten
- **`__objc_classrefs`** (`Class`): Klassenreferenzen
- **`__objc_superrefs`** (`Class`): Superklassenreferenzen
- **`__objc_protorefs`** (`protocol_t *`): Protokollreferenzen
- **`__objc_selrefs`** (`SEL`): Selektorreferenzen
- **`__objc_const`** (`...`): Klassen `r/o` Daten und andere (hoffentlich) konstante Daten
- **`__objc_imageinfo`** (`version, flags`): Wird während des Bildladens verwendet: Version derzeit `0`; Flags geben die Unterstützung für voroptimierte GC an usw.
- **`__objc_protolist`** (`protocol_t *`): Protokollliste
- **`__objc_nlcatlist`** (`category_t`): Zeiger auf Nicht-Lazy-Kategorien, die in diesem Binärformat definiert sind
- **`__objc_catlist`** (`category_t`): Zeiger auf Kategorien, die in diesem Binärformat definiert sind
- **`__objc_nlclslist`** (`classref_t`): Zeiger auf Nicht-Lazy-Objective-C-Klassen, die in diesem Binärformat definiert sind
- **`__objc_classlist`** (`classref_t`): Zeiger auf alle Objective-C-Klassen, die in diesem Binärformat definiert sind

Es verwendet auch einige Abschnitte im **`__TEXT`**-Segment, um konstante Werte zu speichern, wenn es nicht möglich ist, in diesem Abschnitt zu schreiben:

- **`__objc_methname`** (C-String): Methodennamen
- **`__objc_classname`** (C-String): Klassennamen
- **`__objc_methtype`** (C-String): Methodentypen

### Typkodierung

Objective-C verwendet einige Mangling-Techniken, um Selektor- und Variablentypen einfacher und komplexer Typen zu kodieren:

- Primitive Typen verwenden den ersten Buchstaben des Typs `i` für `int`, `c` für `char`, `l` für `long`... und verwenden den Großbuchstaben, falls er unsigned ist (`L` für `unsigned Long`).
- Andere Datentypen, deren Buchstaben verwendet werden oder speziell sind, verwenden andere Buchstaben oder Symbole wie `q` für `long long`, `b` für `bitfields`, `B` für `booleans`, `#` für `classes`, `@` für `id`, `*` für `char pointers`, `^` für generische `pointers` und `?` für `undefined`.
- Arrays, Strukturen und Vereinigungen verwenden `[`, `{` und `(`

#### Beispielmethodendeklaration
```objectivec
- (NSString *)processString:(id)input withOptions:(char *)options andError:(id)error;
```
Der Selektor wäre `processString:withOptions:andError:`

#### Typkodierung

- `id` wird als `@` kodiert
- `char *` wird als `*` kodiert

Die vollständige Typkodierung für die Methode ist:
```less
@24@0:8@16*20^@24
```
#### Detaillierte Aufschlüsselung

1. **Rückgabetyp (`NSString *`)**: Kodiert als `@` mit einer Länge von 24
2. **`self` (Objektinstanz)**: Kodiert als `@`, bei Offset 0
3. **`_cmd` (Selektor)**: Kodiert als `:`, bei Offset 8
4. **Erstes Argument (`char * input`)**: Kodiert als `*`, bei Offset 16
5. **Zweites Argument (`NSDictionary * options`)**: Kodiert als `@`, bei Offset 20
6. **Drittes Argument (`NSError ** error`)**: Kodiert als `^@`, bei Offset 24

**Mit dem Selektor + der Kodierung kannst du die Methode rekonstruieren.**

### **Klassen**

Klassen in Objective-C sind eine Struktur mit Eigenschaften, Methodenzeigern... Es ist möglich, die Struktur `objc_class` im [**Quellcode**](https://opensource.apple.com/source/objc4/objc4-756.2/runtime/objc-runtime-new.h.auto.html) zu finden:
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
Diese Klasse verwendet einige Bits des isa-Feldes, um Informationen über die Klasse anzuzeigen.

Dann hat die Struktur einen Zeiger auf die Struktur `class_ro_t`, die auf der Festplatte gespeichert ist und Attribute der Klasse wie ihren Namen, Basis-Methoden, Eigenschaften und Instanzvariablen enthält.\
Während der Laufzeit wird eine zusätzliche Struktur `class_rw_t` verwendet, die Zeiger enthält, die geändert werden können, wie Methoden, Protokolle, Eigenschaften... 

{{#include ../../../banners/hacktricks-training.md}}
