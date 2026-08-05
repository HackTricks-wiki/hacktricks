# Objekte im Speicher

{{#include ../../../banners/hacktricks-training.md}}

## CFRuntimeClass

CF*-Objekte stammen aus CoreFoundation, das mehr als 50 Objektklassen wie `CFString`, `CFNumber` oder `CFAllocator` bereitstellt.

All diese Klassen sind Instanzen der Klasse `CFRuntimeClass`, die bei einem Aufruf einen Index in die `__CFRuntimeClassTable` zurückgibt. Die CFRuntimeClass ist in [**CFRuntime.h**](https://opensource.apple.com/source/CF/CF-1153.18/CFRuntime.h.auto.html) definiert:
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

Die meisten vom Objective‑C-Runtime verwendeten Daten ändern sich während der Ausführung. Daher verwendet sie mehrere Abschnitte aus der Mach‑O-`__DATA`-Familie von Segmenten im Speicher. Historisch umfassten diese:

- `__objc_msgrefs` (`message_ref_t`): Nachrichtenreferenzen
- `__objc_ivar` (`ivar`): Instanzvariablen
- `__objc_data` (`...`): Veränderliche Daten
- `__objc_classrefs` (`Class`): Klassenreferenzen
- `__objc_superrefs` (`Class`): Superklassenreferenzen
- `__objc_protorefs` (`protocol_t *`): Protokollreferenzen
- `__objc_selrefs` (`SEL`): Selector-Referenzen
- `__objc_const` (`...`): Klassen-Daten mit nur Lesezugriff und andere (hoffentlich) konstante Daten
- `__objc_imageinfo` (`version, flags`): Wird während des Ladens des Images verwendet: Version derzeit `0`; Flags geben die Unterstützung für voroptimiertes GC usw. an
- `__objc_protolist` (`protocol_t *`): Protokollliste
- `__objc_nlcatlist` (`category_t`): Zeiger auf in diesem Binary definierte Non-Lazy Categories
- `__objc_catlist` (`category_t`): Zeiger auf in diesem Binary definierte Categories
- `__objc_nlclslist` (`classref_t`): Zeiger auf in diesem Binary definierte Non-Lazy Objective‑C-Klassen
- `__objc_classlist` (`classref_t`): Zeiger auf alle in diesem Binary definierten Objective‑C-Klassen

Außerdem werden einige Abschnitte im `__TEXT`-Segment verwendet, um Konstanten zu speichern:

- `__objc_methname` (C‑String): Methodennamen
- `__objc_classname` (C‑String): Klassennamen
- `__objc_methtype` (C‑String): Methodentypen

Moderne macOS-/iOS-Versionen (insbesondere auf Apple Silicon) platzieren Objective‑C-/Swift-Metadaten außerdem in:

- `__DATA_CONST`: unveränderliche Objective‑C-Metadaten, die prozessübergreifend schreibgeschützt gemeinsam genutzt werden können (beispielsweise befinden sich viele `__objc_*`-Listen inzwischen hier).
- `__AUTH` / `__AUTH_CONST`: Segmente mit Zeigern, die beim Laden oder zur Verwendungszeit auf arm64e authentifiziert werden müssen (Pointer Authentication). In `__AUTH_CONST` findet sich außerdem `__auth_got` anstelle der älteren alleinigen Verwendung von `__la_symbol_ptr`/`__got`. Berücksichtige beim Instrumentieren oder Hooking sowohl `__got`- als auch `__auth_got`-Einträge in modernen Binaries.

Hintergrundinformationen zur dyld-Pre-Optimierung (z. B. Selector-Unifizierung und Vorberechnung von Klassen/Protokollen) sowie dazu, warum viele dieser Abschnitte bei Herkunft aus dem Shared Cache „bereits angepasst“ sind, findest du in den Apple-Quellen von `objc-opt` und den Notizen zum dyld Shared Cache. Dies beeinflusst, wo und wie du Metadaten zur Laufzeit patchen kannst.

{{#ref}}
../macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.md
{{#endref}}

### Typkodierung

Objective‑C verwendet Mangling, um Selector- und Variablentypen einfacher und komplexer Typen zu codieren:

- Primitive Typen verwenden den ersten Buchstaben des Typs: `i` für `int`, `c` für `char`, `l` für `long` usw.; bei vorzeichenlosen Typen wird der Großbuchstabe verwendet (`L` für `unsigned long`).
- Andere Datentypen verwenden weitere Buchstaben oder Symbole, z. B. `q` für `long long`, `b` für Bitfelder, `B` für boolesche Werte, `#` für Klassen, `@` für `id`, `*` für `char *`, `^` für generische Zeiger und `?` für undefinierte Typen.
- Arrays, Strukturen und Unions verwenden jeweils `[`, `{` bzw. `(`.

#### Beispiel einer Methodendeklaration
```objectivec
- (NSString *)processString:(id)input withOptions:(char *)options andError:(id)error;
```
Der Selector wäre `processString:withOptions:andError:`

#### Type Encoding

- `id` wird als `@` encodiert
- `char *` wird als `*` encodiert

Die vollständige Type Encoding für die Methode lautet:
```less
@24@0:8@16*20^@24
```
#### Detaillierte Aufschlüsselung

1. Rückgabetyp (`NSString *`): Als `@` mit der Länge 24 codiert
2. `self` (Objektinstanz): Als `@` am Offset 0 codiert
3. `_cmd` (Selector): Als `:` am Offset 8 codiert
4. Erstes Argument (`char * input`): Als `*` am Offset 16 codiert
5. Zweites Argument (`NSDictionary * options`): Als `@` am Offset 20 codiert
6. Drittes Argument (`NSError ** error`): Als `^@` am Offset 24 codiert

Mit dem Selector und der Codierung kannst du die Methode rekonstruieren.

### Klassen

Klassen in Objective-C sind C-Strukturen mit Eigenschaften, Methodenzeigern usw. Es ist möglich, die Struktur `objc_class` im [**Quellcode**](https://opensource.apple.com/source/objc4/objc4-756.2/runtime/objc-runtime-new.h.auto.html) zu finden:
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
Diese Klasse verwendet einige Bits des Feldes `isa`, um Informationen über die Klasse anzugeben.

Anschließend enthält die Struktur einen Zeiger auf die auf der Festplatte gespeicherte Struktur `class_ro_t`, die Attribute der Klasse wie ihren Namen, Basismethoden, Properties und Instanzvariablen enthält. Während der Laufzeit wird zusätzlich eine Struktur `class_rw_t` verwendet, die Zeiger auf veränderbare Elemente wie Methoden, Protokolle und Properties enthält.

{{#ref}}
../macos-basic-objective-c.md
{{#endref}}

---

## Moderne Objekt-Repräsentationen im Speicher (arm64e, tagged pointers, Swift)

### Non-pointer `isa` und Pointer Authentication (arm64e)

Auf Apple Silicon und in aktuellen Runtimes ist das Objective-C-`isa` nicht immer ein roher Klassenzeiger. Auf arm64e ist es eine gepackte Struktur, die auch einen Pointer Authentication Code (PAC) enthalten kann. Je nach Plattform kann sie Felder wie `nonpointer`, `has_assoc`, `weakly_referenced`, `extra_rc` sowie den Klassenzeiger selbst enthalten (verschoben oder signiert). Das bedeutet, dass das blinde Dereferenzieren der ersten 8 Bytes eines Objective-C-Objekts nicht immer einen gültigen `Class`-Zeiger ergibt.<sup>[[2]](#references)</sup>

Praktische Hinweise beim Debugging auf arm64e:

- LLDB entfernt PAC-Bits normalerweise für dich, wenn Objective-C-Objekte mit `po` ausgegeben werden. Bei der Arbeit mit rohen Zeigern musst du die Authentifizierung jedoch möglicherweise manuell entfernen:

```lldb
(lldb) expr -l objc++ -- #include <ptrauth.h>
(lldb) expr -l objc++ -- void *raw = ptrauth_strip((void*)0x000000016f123abc, ptrauth_key_asda);
(lldb) expr -l objc++ -O -- (Class)object_getClass((id)raw)
```

- Viele Funktions-/Datenzeiger in Mach-O befinden sich in `__AUTH`/`__AUTH_CONST` und müssen vor der Verwendung authentifiziert werden. Wenn du Interposing oder Re-Binding durchführst (z. B. im fishhook-Stil), musst du sicherstellen, dass du zusätzlich zu `__got` auch `__auth_got` verarbeitest.

Eine ausführliche Untersuchung der Sprach-/ABI-Garantien und der in Clang/LLVM verfügbaren Intrinsics aus `<ptrauth.h>` findest du in der Referenz am Ende dieser Seite.<sup>[[1]](#references)</sup>

### Tagged-pointer-Objekte

Einige Foundation-Klassen vermeiden Heap-Allokation, indem sie die Nutzdaten des Objekts direkt im Pointer-Wert codieren (tagged pointers). Die Erkennung unterscheidet sich je nach Plattform (z. B. höchstwertiges Bit auf arm64, niederwertigstes Bit auf x86_64 macOS). Tagged objects verfügen nicht über ein reguläres, im Speicher gespeichertes `isa`; die Runtime löst die Klasse anhand der Tag-Bits auf.<sup>[[2]](#references)</sup> Beim Untersuchen beliebiger `id`-Werte:

- Verwende Runtime-APIs, anstatt das `isa`-Feld direkt zu untersuchen: `object_getClass(obj)` / `[obj class]`.
- In LLDB gibt `po (id)0xADDR` tagged-pointer-Instanzen korrekt aus, da die Runtime zur Auflösung der Klasse herangezogen wird.

### Swift-Heap-Objekte und Metadaten

Reine Swift-Klassen sind ebenfalls Objekte mit einem Header, der auf Swift-Metadaten zeigt (nicht auf Objective-C-`isa`). Um aktive Swift-Prozesse zu untersuchen, ohne sie zu verändern, kannst du `swift-inspect` aus der Swift-Toolchain verwenden. Dieses nutzt die Remote Mirror library, um Runtime-Metadaten zu lesen:
```bash
# Xcode toolchain (or Swift.org toolchain) provides swift-inspect
swift-inspect dump-raw-metadata <pid-or-name>
swift-inspect dump-arrays <pid-or-name>
# On Darwin additionally:
swift-inspect dump-concurrency <pid-or-name>
```
Dies ist sehr nützlich, um Swift-Heap-Objekte und Protokollkonformitäten beim Reverse Engineering von gemischten Swift/ObjC-Apps zu erfassen.

---

## Cheatsheet zur Laufzeitinspektion (LLDB / Frida)

### LLDB

- Objekt oder Klasse von einem rohen Pointer ausgeben:
```lldb
(lldb) expr -l objc++ -O -- (id)0x0000000101234560
(lldb) expr -l objc++ -O -- (Class)object_getClass((id)0x0000000101234560)
```
- Objective-C-Klasse anhand eines Zeigers auf das self einer Objektmethode in einem breakpoint untersuchen:
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
- Lies den Speicher eines bekannten Klassenobjekts, um beim Reverse Engineering von Methodenlisten zu `class_ro_t` / `class_rw_t` zu gelangen:
```lldb
(lldb) image lookup -r -n _OBJC_CLASS_$_NSFileManager
(lldb) memory read -fx -s8 0xADDRESS_OF_CLASS_OBJECT
```
### Frida (Objective‑C und Swift)

Frida bietet High-Level-Runtime-Bridges, die sehr nützlich sind, um Live-Objekte ohne Symbole zu entdecken und zu instrumentieren:

- Klassen und Methoden aufzählen, die tatsächlichen Klassennamen zur Laufzeit auflösen und Objective‑C-Selectoren abfangen:
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
- Swift bridge: Swift-Typen enumerieren und mit Swift-Instanzen interagieren (erfordert eine aktuelle Frida-Version; sehr nützlich für Apple-Silicon-Ziele).

---

## Referenzen

- [1] [Clang/LLVM: Pointer Authentication und die ptrauth.h-Intrinsics (arm64e ABI)](https://clang.llvm.org/docs/PointerAuthentication.html)
- [2] [Apple objc runtime headers - objc-object.h (tagged pointers, non-pointer isa usw.)](https://opensource.apple.com/source/objc4/objc4-818.2/runtime/objc-object.h.auto.html)

{{#include ../../../banners/hacktricks-training.md}}
