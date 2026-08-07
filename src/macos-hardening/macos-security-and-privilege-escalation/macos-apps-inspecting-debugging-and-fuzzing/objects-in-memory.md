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

Die meisten vom Objective-C runtime verwendeten Daten ändern sich während der Ausführung. Daher verwendet es mehrere Abschnitte aus der Mach-O-`__DATA`-Familie von Segmenten im Speicher. Historisch gehörten dazu:

- `__objc_msgrefs` (`message_ref_t`): Message-Referenzen
- `__objc_ivar` (`ivar`): Instanzvariablen
- `__objc_data` (`...`): Veränderliche Daten
- `__objc_classrefs` (`Class`): Klassenreferenzen
- `__objc_superrefs` (`Class`): Superklassenreferenzen
- `__objc_protorefs` (`protocol_t *`): Protocol-Referenzen
- `__objc_selrefs` (`SEL`): Selector-Referenzen
- `__objc_const` (`...`): Klassen-Read-only-Daten und andere (hoffentlich) konstante Daten
- `__objc_imageinfo` (`version, flags`): Wird während des Image-Ladevorgangs verwendet: Die Version ist derzeit `0`; Flags geben die Unterstützung für voroptimiertes GC usw. an.
- `__objc_protolist` (`protocol_t *`): Protocol-Liste
- `__objc_nlcatlist` (`category_t`): Zeiger auf in diesem Binary definierte Non-Lazy Categories
- `__objc_catlist` (`category_t`): Zeiger auf in diesem Binary definierte Categories
- `__objc_nlclslist` (`classref_t`): Zeiger auf in diesem Binary definierte Non-Lazy Objective-C-Klassen
- `__objc_classlist` (`classref_t`): Zeiger auf alle in diesem Binary definierten Objective-C-Klassen

Außerdem verwendet es einige Abschnitte im `__TEXT`-Segment zum Speichern von Konstanten:

- `__objc_methname` (C-String): Methodennamen
- `__objc_classname` (C-String): Klassennamen
- `__objc_methtype` (C-String): Methodentypen

Modernes macOS/iOS (insbesondere auf Apple Silicon) speichert Objective-C-/Swift-Metadaten außerdem in:

- `__DATA_CONST`: Unveränderliche Objective-C-Metadaten, die prozessübergreifend schreibgeschützt gemeinsam genutzt werden können (beispielsweise befinden sich viele `__objc_*`-Listen inzwischen hier).
- `__AUTH` / `__AUTH_CONST`: Segmente, die Zeiger enthalten, die beim Laden oder zur Verwendungszeit auf arm64e authentifiziert werden müssen (Pointer Authentication). In modernen Binaries findet man außerdem `__auth_got` in `__AUTH_CONST` anstelle der alten Einträge `__la_symbol_ptr`/`__got`. Beim Instrumentieren oder Hooking muss berücksichtigt werden, dass moderne Binaries sowohl `__got`- als auch `__auth_got`-Einträge enthalten können.

Hintergrund zur dyld-Pre-Optimierung (z. B. Selector-Uniquing sowie Vorberechnung von Klassen und Protocols) und dazu, warum viele dieser Abschnitte aus dem Shared Cache „bereits korrigiert“ sind, findet sich in den Apple-Quellen von `objc-opt` und den Hinweisen zum dyld Shared Cache. Dies beeinflusst, wo und wie Metadaten zur Laufzeit gepatcht werden können.

{{#ref}}
../macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.md
{{#endref}}

### Typkodierung

Objective-C verwendet Name Mangling, um Selector- und Variablentypen einfacher und komplexer Typen zu kodieren:

- Primitive Typen verwenden den ersten Buchstaben ihres Typs: `i` für `int`, `c` für `char`, `l` für `long` usw. Bei vorzeichenlosen Typen wird der Großbuchstabe verwendet (`L` für `unsigned long`).
- Andere Datentypen verwenden weitere Buchstaben oder Symbole, etwa `q` für `long long`, `b` für Bitfelder, `B` für boolesche Werte, `#` für Klassen, `@` für `id`, `*` für `char *`, `^` für generische Zeiger und `?` für undefinierte Typen.
- Arrays, Strukturen und Unions verwenden jeweils `[`, `{` und `(`.

#### Beispiel einer Methodendeklaration
```objectivec
- (NSString *)processString:(id)input withOptions:(char *)options andError:(id)error;
```
Der Selector wäre `processString:withOptions:andError:`

#### Typkodierung

- `id` wird als `@` kodiert
- `char *` wird als `*` kodiert

Die vollständige Typkodierung für die Methode lautet:
```less
@24@0:8@16*20^@24
```
#### Detaillierte Aufschlüsselung

1. Rückgabetyp (`NSString *`): Als `@` mit der Länge 24 codiert
2. `self` (Objektinstanz): Als `@` codiert, am Offset 0
3. `_cmd` (Selector): Als `:` codiert, am Offset 8
4. Erstes Argument (`char * input`): Als `*` codiert, am Offset 16
5. Zweites Argument (`NSDictionary * options`): Als `@` codiert, am Offset 20
6. Drittes Argument (`NSError ** error`): Als `^@` codiert, am Offset 24

Mit dem Selector und der Codierung kann die Methode rekonstruiert werden.

### Klassen

Klassen in Objective-C sind C-Strukturen mit Properties, Methodenzeigern usw. Die Struktur `objc_class` kann im [**Quellcode**](https://opensource.apple.com/source/objc4/objc4-756.2/runtime/objc-runtime-new.h.auto.html) gefunden werden:
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

Anschließend enthält das Struct einen Pointer auf das Struct `class_ro_t`, das auf der Festplatte gespeichert ist und Attribute der Klasse wie ihren Namen, Basismethoden, Properties und Instanzvariablen enthält. Während der Laufzeit wird zusätzlich eine Struktur `class_rw_t` verwendet, die Pointer enthält, die geändert werden können, etwa Methoden, Protokolle und Properties.

{{#ref}}
../macos-basic-objective-c.md
{{#endref}}

---

## Moderne Objekt-Repräsentationen im Speicher (arm64e, tagged pointers, Swift)

### Non-pointer `isa` und Pointer Authentication (arm64e)

Auf Apple Silicon und in aktuellen Runtimes ist das Objective-C-`isa` nicht immer ein unveränderter Klassen-Pointer. Auf arm64e handelt es sich um eine gepackte Struktur, die zusätzlich einen Pointer Authentication Code (PAC) enthalten kann. Je nach Plattform kann sie Felder wie `nonpointer`, `has_assoc`, `weakly_referenced`, `extra_rc` und den Klassen-Pointer selbst enthalten (verschoben oder signiert). Das bedeutet, dass das blinde Dereferenzieren der ersten 8 Bytes eines Objective-C-Objekts nicht immer einen gültigen `Class`-Pointer ergibt.<sup>[[2]](#references)</sup>

Praktische Hinweise für das Debugging auf arm64e:

- LLDB entfernt PAC-Bits normalerweise für dich, wenn Objective-C-Objekte mit `po` ausgegeben werden. Bei der Arbeit mit Raw-Pointern musst du die Authentifizierung jedoch möglicherweise manuell entfernen:

```lldb
(lldb) expr -l objc++ -- #include <ptrauth.h>
(lldb) expr -l objc++ -- void *raw = ptrauth_strip((void*)0x000000016f123abc, ptrauth_key_asda);
(lldb) expr -l objc++ -O -- (Class)object_getClass((id)raw)
```

- Viele Funktions-/Daten-Pointer in Mach-O befinden sich in `__AUTH`/`__AUTH_CONST` und erfordern vor ihrer Verwendung eine Authentifizierung. Wenn du Interposing oder Re-Binding durchführst (beispielsweise im fishhook-Stil), musst du sicherstellen, dass du zusätzlich zu `__got` auch `__auth_got` behandelst.

Eine ausführliche Erklärung der Garantien von Sprache und ABI sowie der in Clang/LLVM verfügbaren Intrinsics aus `<ptrauth.h>` findest du in der Referenz am Ende dieser Seite.<sup>[[1]](#references)</sup>

### Tagged pointer objects

Einige Foundation-Klassen vermeiden Heap-Allokationen, indem sie die Payload des Objekts direkt im Pointer-Wert codieren (tagged pointers). Die Erkennung unterscheidet sich je nach Plattform (beispielsweise höchstwertiges Bit auf arm64, niederwertigstes Bit auf x86_64 macOS). Tagged objects besitzen kein reguläres, im Speicher gespeichertes `isa`; die Runtime ermittelt die Klasse anhand der Tag-Bits.<sup>[[2]](#references)</sup> Bei der Untersuchung beliebiger `id`-Werte:

- Verwende Runtime-APIs statt direkt auf das `isa`-Feld zuzugreifen: `object_getClass(obj)` / `[obj class]`.
- In LLDB gibt `po (id)0xADDR` tagged pointer instances korrekt aus, da die Runtime zur Ermittlung der Klasse herangezogen wird.

### Swift-Heap-Objekte und Metadaten

Reine Swift-Klassen sind ebenfalls Objekte mit einem Header, der auf Swift-Metadaten (nicht auf Objective-C-`isa`) verweist. Um aktive Swift-Prozesse zu untersuchen, ohne sie zu verändern, kannst du das `swift-inspect` der Swift-Toolchain verwenden, das die Remote Mirror library nutzt, um Runtime-Metadaten zu lesen:
```bash
# Xcode toolchain (or Swift.org toolchain) provides swift-inspect
swift-inspect dump-raw-metadata <pid-or-name>
swift-inspect dump-arrays <pid-or-name>
# On Darwin additionally:
swift-inspect dump-concurrency <pid-or-name>
```
Dies ist sehr nützlich, um Swift-Heap-Objekte und Protocol-Konformitäten beim Reverse Engineering gemischter Swift/ObjC-Apps zuzuordnen.

---

## Cheatsheet zur Runtime-Inspektion (LLDB / Frida)

### LLDB

- Objekt oder Klasse aus einem rohen Pointer ausgeben:
```lldb
(lldb) expr -l objc++ -O -- (id)0x0000000101234560
(lldb) expr -l objc++ -O -- (Class)object_getClass((id)0x0000000101234560)
```
- Objective-C-Klasse anhand eines Zeigers auf das `self` einer Objekt-Methode in einem Breakpoint untersuchen:
```lldb
(lldb) br se -n '-[NSFileManager fileExistsAtPath:]'
(lldb) r
... breakpoint hit ...
(lldb) po (id)$x0                 # self
(lldb) expr -l objc++ -O -- (Class)object_getClass((id)$x0)
```
- Dump sections, die Objective-C metadata enthalten (Hinweis: Viele befinden sich jetzt in `__DATA_CONST` / `__AUTH_CONST`):
```lldb
(lldb) image dump section --section __DATA_CONST.__objc_classlist
(lldb) image dump section --section __DATA_CONST.__objc_selrefs
(lldb) image dump section --section __AUTH_CONST.__auth_got
```
- Lies den Speicher eines bekannten Klassenobjekts, um beim Reverse Engineering von Methodenlisten zu `class_ro_t` / `class_rw_t` zu pivotieren:
```lldb
(lldb) image lookup -r -n _OBJC_CLASS_$_NSFileManager
(lldb) memory read -fx -s8 0xADDRESS_OF_CLASS_OBJECT
```
### Frida (Objective‑C und Swift)

Frida stellt High-Level-Runtime-Bridges bereit, die sehr praktisch sind, um Live-Objekte ohne Symbole zu entdecken und zu instrumentieren:

- Klassen und Methoden auflisten, tatsächliche Klassennamen zur Laufzeit auflösen und Objective‑C-Selectoren abfangen:
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
- Swift bridge: Swift-Typen enumerieren und mit Swift-Instanzen interagieren (erfordert eine aktuelle Frida-Version; sehr nützlich bei Apple-Silicon-Zielen).

---

## Referenzen


- [1] [Clang/LLVM: Pointer Authentication und die ptrauth.h-Intrinsics (arm64e ABI)](https://clang.llvm.org/docs/PointerAuthentication.html)
- [2] [Apple objc runtime headers - objc-object.h (tagged pointers, non-pointer isa usw.)](https://opensource.apple.com/source/objc4/objc4-818.2/runtime/objc-object.h.auto.html)

{{#include ../../../banners/hacktricks-training.md}}
