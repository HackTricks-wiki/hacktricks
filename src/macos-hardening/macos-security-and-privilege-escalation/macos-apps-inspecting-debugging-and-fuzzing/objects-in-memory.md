# Objekte im Speicher

{{#include ../../../banners/hacktricks-training.md}}

## CFRuntimeClass

CF*-Objekte stammen aus CoreFoundation, das mehr als 50 Objektklassen wie `CFString`, `CFNumber` oder `CFAllocator` bereitstellt.

All diese Klassen sind Instanzen der Klasse `CFRuntimeClass`, die bei ihrem Aufruf einen Index in die `__CFRuntimeClassTable` zurückgibt. Die CFRuntimeClass ist in [**CFRuntime.h**](https://opensource.apple.com/source/CF/CF-1153.18/CFRuntime.h.auto.html) definiert:
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

Die meisten von der Objective‑C runtime verwendeten Daten ändern sich während der Ausführung. Daher verwendet sie mehrere Abschnitte aus der Mach‑O-`__DATA`-Familie von Segmenten im Speicher. Historisch umfassten diese:

- `__objc_msgrefs` (`message_ref_t`): Message-Referenzen
- `__objc_ivar` (`ivar`): Instanzvariablen
- `__objc_data` (`...`): Veränderliche Daten
- `__objc_classrefs` (`Class`): Class-Referenzen
- `__objc_superrefs` (`Class`): Superclass-Referenzen
- `__objc_protorefs` (`protocol_t *`): Protocol-Referenzen
- `__objc_selrefs` (`SEL`): Selector-Referenzen
- `__objc_const` (`...`): R/O-Daten von Classes und andere (hoffentlich) konstante Daten
- `__objc_imageinfo` (`version, flags`): Wird während des image load verwendet: Die Version ist derzeit `0`; Flags geben die Unterstützung für preoptimized GC usw. an.
- `__objc_protolist` (`protocol_t *`): Protocol-Liste
- `__objc_nlcatlist` (`category_t`): Pointer auf in diesem Binary definierte Non-Lazy Categories
- `__objc_catlist` (`category_t`): Pointer auf in diesem Binary definierte Categories
- `__objc_nlclslist` (`classref_t`): Pointer auf in diesem Binary definierte Non-Lazy Objective‑C Classes
- `__objc_classlist` (`classref_t`): Pointer auf alle in diesem Binary definierten Objective‑C Classes

Außerdem verwendet sie einige Abschnitte im `__TEXT`-Segment zum Speichern von Konstanten:

- `__objc_methname` (C‑String): Methodennamen
- `__objc_classname` (C‑String): Class-Namen
- `__objc_methtype` (C‑String): Method-Typen

Modernes macOS/iOS (insbesondere auf Apple Silicon) speichert Objective‑C/Swift-Metadaten außerdem in:

- `__DATA_CONST`: Unveränderliche Objective‑C-Metadaten, die prozessübergreifend schreibgeschützt gemeinsam genutzt werden können (beispielsweise befinden sich viele `__objc_*`-Listen inzwischen hier).
- `__AUTH` / `__AUTH_CONST`: Segmente mit Pointern, die beim Laden oder zur Nutzungszeit auf arm64e authentifiziert werden müssen (Pointer Authentication). In modernen Binaries findet sich in `__AUTH_CONST` außerdem `__auth_got` anstelle der bisherigen `__la_symbol_ptr`/`__got`. Denke beim Instrumentieren oder Hooking daran, sowohl `__got`- als auch `__auth_got`-Einträge in modernen Binaries zu berücksichtigen.

Hintergrundinformationen zur dyld pre-optimization (z. B. Selector-Uniquing und die Vorberechnung von Classes/Protocols) und dazu, warum viele dieser Abschnitte bei Daten aus dem shared cache „bereits korrigiert“ sind, findest du in den Apple-Quellen von `objc-opt` und den Notizen zum dyld shared cache. Dies beeinflusst, wo und wie du Metadaten zur Laufzeit patchen kannst.

{{#ref}}
../macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.md
{{#endref}}

### Type Encoding

Objective‑C verwendet Mangling, um Selector- und Variablentypen einfacher und komplexer Typen zu codieren:

- Primitive Typen verwenden den ersten Buchstaben des Typs: `i` für `int`, `c` für `char`, `l` für `long` usw.; bei unsigned Typen wird der Großbuchstabe verwendet (`L` für `unsigned long`).
- Andere Datentypen verwenden weitere Buchstaben oder Symbole, etwa `q` für `long long`, `b` für Bitfelder, `B` für Booleans, `#` für Classes, `@` für `id`, `*` für `char *`, `^` für generische Pointer und `?` für undefinierte Typen.
- Arrays, Strukturen und Unions verwenden jeweils `[`, `{` beziehungsweise `(`.

#### Beispiel einer Methodendeklaration
```objectivec
- (NSString *)processString:(id)input withOptions:(char *)options andError:(id)error;
```
Der Selector wäre `processString:withOptions:andError:`

#### Typenkodierung

- `id` wird als `@` kodiert
- `char *` wird als `*` kodiert

Die vollständige Typenkodierung für die Methode lautet:
```less
@24@0:8@16*20^@24
```
#### Detaillierte Aufschlüsselung

1. Rückgabetyp (`NSString *`): Als `@` mit der Länge 24 codiert
2. `self` (Objektinstanz): Als `@` codiert, bei Offset 0
3. `_cmd` (Selector): Als `:` codiert, bei Offset 8
4. Erstes Argument (`char * input`): Als `*` codiert, bei Offset 16
5. Zweites Argument (`NSDictionary * options`): Als `@` codiert, bei Offset 20
6. Drittes Argument (`NSError ** error`): Als `^@` codiert, bei Offset 24

Mit dem Selector und der Codierung kannst du die Methode rekonstruieren.

### Klassen

Klassen in Objective-C sind C-Strukturen mit Properties, Methoden-Pointern usw. Die Struktur `objc_class` kann im [**Quellcode**](https://opensource.apple.com/source/objc4/objc4-756.2/runtime/objc-runtime-new.h.auto.html) gefunden werden:
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
Diese Klasse verwendet einige Bits des Felds `isa`, um Informationen über die Klasse anzugeben.

Anschließend enthält die Struktur einen Pointer auf die auf der Festplatte gespeicherte Struktur `class_ro_t`, die Attribute der Klasse wie ihren Namen, base methods, properties und instance variables enthält. Während der Laufzeit wird zusätzlich eine Struktur `class_rw_t` verwendet, die Pointer auf veränderbare Elemente wie methods, protocols und properties enthält.

{{#ref}}
../macos-basic-objective-c.md
{{#endref}}

---

## Moderne object representations im Speicher (arm64e, tagged pointers, Swift)

### Non-pointer `isa` und Pointer Authentication (arm64e)

Auf Apple Silicon und in neueren Runtimes ist das Objective-C-`isa` nicht immer ein roher Klassen-Pointer. Auf arm64e handelt es sich um eine gepackte Struktur, die auch einen Pointer Authentication Code (PAC) enthalten kann. Je nach Plattform kann sie Felder wie `nonpointer`, `has_assoc`, `weakly_referenced`, `extra_rc` und den Klassen-Pointer selbst enthalten (verschoben oder signiert). Das bedeutet, dass das blinde Dereferenzieren der ersten 8 Bytes eines Objective-C-Objekts nicht immer einen gültigen `Class`-Pointer ergibt.<sup>[2]</sup>

Praktische Hinweise beim Debugging auf arm64e:

- LLDB entfernt PAC-Bits normalerweise für dich, wenn Objective-C-Objekte mit `po` ausgegeben werden. Bei der Arbeit mit raw pointers musst du die Authentication jedoch möglicherweise manuell entfernen:

```lldb
(lldb) expr -l objc++ -- #include <ptrauth.h>
(lldb) expr -l objc++ -- void *raw = ptrauth_strip((void*)0x000000016f123abc, ptrauth_key_asda);
(lldb) expr -l objc++ -O -- (Class)object_getClass((id)raw)
```

- Viele function/data pointers in Mach-O befinden sich in `__AUTH`/`__AUTH_CONST` und benötigen vor der Verwendung eine Authentication. Wenn du interposing oder re-binding durchführst (z. B. im Stil von fishhook), stelle sicher, dass du zusätzlich zum älteren `__got` auch `__auth_got` behandelst.

Eine ausführliche Erklärung der language/ABI guarantees sowie der in Clang/LLVM verfügbaren Intrinsics aus `<ptrauth.h>` findest du in der Referenz am Ende dieser Seite.<sup>[1]</sup>

### Tagged pointer objects

Einige Foundation-Klassen vermeiden Heap-Allocation, indem sie die Payload des Objekts direkt im Pointer-Wert codieren (tagged pointers). Die Erkennung unterscheidet sich je nach Plattform (z. B. das höchstwertige Bit auf arm64 und das niedrigstwertige Bit auf x86_64 macOS). Tagged objects besitzen kein reguläres, im Speicher gespeichertes `isa`; die Runtime ermittelt die Klasse anhand der tag bits.<sup>[2]</sup> Beim Inspecting beliebiger `id`-Werte:

- Verwende Runtime-APIs statt das `isa`-Feld direkt zu untersuchen: `object_getClass(obj)` / `[obj class]`.
- In LLDB gibt `po (id)0xADDR` tagged pointer instances korrekt aus, da die Runtime zur Ermittlung der Klasse konsultiert wird.

### Swift heap objects und metadata

Reine Swift-Klassen sind ebenfalls objects mit einem Header, der auf Swift metadata (nicht auf Objective-C-`isa`) verweist. Um laufende Swift-Prozesse zu introspecten, ohne sie zu verändern, kannst du das `swift-inspect` der Swift toolchain verwenden, das die Remote Mirror library nutzt, um runtime metadata zu lesen:
```bash
# Xcode toolchain (or Swift.org toolchain) provides swift-inspect
swift-inspect dump-raw-metadata <pid-or-name>
swift-inspect dump-arrays <pid-or-name>
# On Darwin additionally:
swift-inspect dump-concurrency <pid-or-name>
```
Dies ist sehr nützlich, um Swift-Heap-Objekte und Protocol-Conformances beim Reverse Engineering von gemischten Swift/ObjC-Apps zu erfassen.

---

## Cheatsheet zur Runtime-Inspektion (LLDB / Frida)

### LLDB

- Objekt oder Klasse aus einem Raw Pointer ausgeben:
```lldb
(lldb) expr -l objc++ -O -- (id)0x0000000101234560
(lldb) expr -l objc++ -O -- (Class)object_getClass((id)0x0000000101234560)
```
- Objective-C-Klasse aus einem Pointer auf das `self` einer Objektmethode in einem Breakpoint untersuchen:
```lldb
(lldb) br se -n '-[NSFileManager fileExistsAtPath:]'
(lldb) r
... breakpoint hit ...
(lldb) po (id)$x0                 # self
(lldb) expr -l objc++ -O -- (Class)object_getClass((id)$x0)
```
- Dump die Abschnitte, die Objective-C-Metadaten enthalten (Hinweis: Viele befinden sich jetzt in `__DATA_CONST` / `__AUTH_CONST`):
```lldb
(lldb) image dump section --section __DATA_CONST.__objc_classlist
(lldb) image dump section --section __DATA_CONST.__objc_selrefs
(lldb) image dump section --section __AUTH_CONST.__auth_got
```
- Lies den Speicher eines bekannten Klassenobjekts, um beim Reverse Engineering von Methodenlisten zu `class_ro_t` / `class_rw_t` überzugehen:
```lldb
(lldb) image lookup -r -n _OBJC_CLASS_$_NSFileManager
(lldb) memory read -fx -s8 0xADDRESS_OF_CLASS_OBJECT
```
### Frida (Objective-C und Swift)

Frida stellt High-Level-Runtime-Bridges bereit, die sehr nützlich sind, um Live-Objekte ohne Symbole zu entdecken und zu instrumentieren:

- Klassen und Methoden aufzählen, tatsächliche Klassennamen zur Laufzeit auflösen und Objective-C-Selektoren abfangen:
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
- Swift bridge: Swift-Typen aufzählen und mit Swift-Instanzen interagieren (erfordert eine aktuelle Frida-Version; sehr nützlich für Apple-Silicon-Ziele).

---

## Referenzen

- [1] [Clang/LLVM: Pointer Authentication und die ptrauth.h intrinsics (arm64e ABI)](https://clang.llvm.org/docs/PointerAuthentication.html)
- [2] [Apple objc runtime headers - objc-object.h (tagged pointers, non‑pointer isa usw.)](https://opensource.apple.com/source/objc4/objc4-818.2/runtime/objc-object.h.auto.html)

{{#include ../../../banners/hacktricks-training.md}}
