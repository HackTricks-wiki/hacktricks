# Objekte im Speicher

{{#include ../../../banners/hacktricks-training.md}}

## CFRuntimeClass

CF* objects come from CoreFoundation, which provides more than 50 classes of objects like `CFString`, `CFNumber` or `CFAllocator`.

All these classes are instances of the class `CFRuntimeClass`, which when called it returns an index to the `__CFRuntimeClassTable`. The CFRuntimeClass is defined in [**CFRuntime.h**](https://opensource.apple.com/source/CF/CF-1153.18/CFRuntime.h.auto.html):
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

Die meisten Daten, die die Objective‑C Runtime verwendet, ändern sich während der Ausführung, daher nutzt sie eine Reihe von Sektionen aus der Mach‑O `__DATA`-Familie von Segments im Speicher. Historisch gehörten dazu:

- `__objc_msgrefs` (`message_ref_t`): Nachrichtenreferenzen
- `__objc_ivar` (`ivar`): Instanzvariablen
- `__objc_data` (`...`): Mutable Daten
- `__objc_classrefs` (`Class`): Klassenreferenzen
- `__objc_superrefs` (`Class`): Superclass-Referenzen
- `__objc_protorefs` (`protocol_t *`): Protokollreferenzen
- `__objc_selrefs` (`SEL`): Selector-Referenzen
- `__objc_const` (`...`): Klassen r/o Daten und andere (hoffentlich) konstante Daten
- `__objc_imageinfo` (`version, flags`): Wird beim Image-Load verwendet: Version derzeit `0`; Flags spezifizieren z. B. voroptimierte GC-Unterstützung.
- `__objc_protolist` (`protocol_t *`): Protokollliste
- `__objc_nlcatlist` (`category_t`): Pointer auf Non-Lazy Categories, die in diesem Binary definiert sind
- `__objc_catlist` (`category_t`): Pointer auf Categories, die in diesem Binary definiert sind
- `__objc_nlclslist` (`classref_t`): Pointer auf Non-Lazy Objective‑C Klassen, die in diesem Binary definiert sind
- `__objc_classlist` (`classref_t`): Pointer auf alle Objective‑C Klassen, die in diesem Binary definiert sind

Es verwendet außerdem einige Sektionen im `__TEXT`-Segment, um Konstanten zu speichern:

- `__objc_methname` (C‑String): Methodennamen
- `__objc_classname` (C‑String): Klassennamen
- `__objc_methtype` (C‑String): Methodentypen

Modernes macOS/iOS (insbesondere auf Apple Silicon) legt Objective‑C/Swift‑Metadaten außerdem in:

- `__DATA_CONST`: unveränderliche Objective‑C‑Metadaten, die schreibgeschützt zwischen Prozessen geteilt werden können (zum Beispiel liegen viele `__objc_*`-Listen jetzt hier).
- `__AUTH` / `__AUTH_CONST`: Segmente, die Zeiger enthalten, die beim Laden oder zur Laufzeit auf arm64e authentifiziert werden müssen (Pointer Authentication). Sie werden außerdem `__auth_got` in `__AUTH_CONST` sehen, anstelle der legacy `__la_symbol_ptr`/`__got`-Einträge. Beim instrumenting or hooking denken Sie daran, sowohl `__got`- als auch `__auth_got`-Einträge in modernen Binaries zu berücksichtigen.

Für Hintergrundinformationen zu dyld pre‑optimization (z. B. selector uniquing und class/protocol precomputation) und warum viele dieser Sektionen beim Laden aus dem shared cache bereits "fixed up" sind, sehen Sie sich die Apple `objc-opt`-Quellen und dyld shared cache-Notizen an. Das beeinflusst, wo und wie Sie Metadaten zur Laufzeit patchen können.

{{#ref}}
../macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.md
{{#endref}}

### Type Encoding

Objective‑C verwendet Mangling, um Selector- und Variablentypen einfacher und komplexer Typen zu kodieren:

- Primitive Typen verwenden den Anfangsbuchstaben des Typs: `i` für `int`, `c` für `char`, `l` für `long` ... und verwenden Großbuchstaben im Fall von unsigned (`L` für `unsigned long`).
- Andere Datentypen verwenden andere Buchstaben oder Symbole wie `q` für `long long`, `b` für bitfields, `B` für booleans, `#` für classes, `@` für `id`, `*` für `char *`, `^` für generische Pointer und `?` für undefined.
- Arrays, Strukturen und Unions verwenden jeweils `[`, `{` und `(`.

#### Beispiel Methodendeklaration
```objectivec
- (NSString *)processString:(id)input withOptions:(char *)options andError:(id)error;
```
Der Selector wäre `processString:withOptions:andError:`

#### Type Encoding

- `id` wird als `@` kodiert
- `char *` wird als `*` kodiert

Die vollständige Type Encoding für die Methode ist:
```less
@24@0:8@16*20^@24
```
#### Detailed Breakdown

1. Rückgabetyp (`NSString *`): Kodiert als `@` mit Länge 24
2. `self` (Objektinstanz): Kodiert als `@`, bei Offset 0
3. `_cmd` (Selector): Kodiert als `:`, bei Offset 8
4. Erstes Argument (`char * input`): Kodiert als `*`, bei Offset 16
5. Zweites Argument (`NSDictionary * options`): Kodiert als `@`, bei Offset 20
6. Drittes Argument (`NSError ** error`): Kodiert als `^@`, bei Offset 24

Mit dem Selector + der Kodierung lässt sich die Methode rekonstruieren.

### Classes

Klassen in Objective‑C sind C‑Strukturen mit Eigenschaften, Methodenzeigern usw. Man findet die Struktur `objc_class` im [**source code**](https://opensource.apple.com/source/objc4/objc4-756.2/runtime/objc-runtime-new.h.auto.html):
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
This class uses some bits of the `isa` field to indicate information about the class.

Then, the struct has a pointer to the struct `class_ro_t` stored on disk which contains attributes of the class like its name, base methods, properties and instance variables. During runtime an additional structure `class_rw_t` is used containing pointers which can be altered such as methods, protocols, properties.

{{#ref}}
../macos-basic-objective-c.md
{{#endref}}

---

## Moderne Objektrepräsentationen im Speicher (arm64e, getaggte Pointer, Swift)

### Nicht‑Pointer-`isa` und Pointer-Authentifizierung (arm64e)

Auf Apple Silicon und in aktuellen Runtimes ist das Objective‑C-`isa` nicht immer ein roher Klassenzeiger. Auf arm64e ist es eine gepackte Struktur, die auch einen Pointer Authentication Code (PAC) tragen kann. Je nach Plattform kann sie Felder wie `nonpointer`, `has_assoc`, `weakly_referenced`, `extra_rc` und den Klassenzeiger selbst (verschoben oder signiert) enthalten. Das bedeutet, dass das blinde Dereferenzieren der ersten 8 Bytes eines Objective‑C-Objekts nicht immer einen gültigen `Class`-Zeiger liefert.

Praktische Hinweise beim Debuggen auf arm64e:

- LLDB wird normalerweise die PAC-Bits für dich entfernen, wenn Objective‑C-Objekte mit `po` ausgegeben werden, aber beim Arbeiten mit rohen Zeigern musst du die Authentifizierung ggf. manuell entfernen:

```lldb
(lldb) expr -l objc++ -- #include <ptrauth.h>
(lldb) expr -l objc++ -- void *raw = ptrauth_strip((void*)0x000000016f123abc, ptrauth_key_asda);
(lldb) expr -l objc++ -O -- (Class)object_getClass((id)raw)
```

- Viele Funktions-/Datenszeiger in Mach‑O liegen in `__AUTH`/`__AUTH_CONST` und erfordern eine Authentifizierung vor der Verwendung. Wenn du interponierst oder neu bindest (z. B. im fishhook‑Stil), stelle sicher, dass du zusätzlich zu dem legacy `__got` auch `__auth_got` behandelst.

Für einen tiefen Einblick in Sprach-/ABI-Garantien und die von Clang/LLVM verfügbaren `<ptrauth.h>`-Intrinsics siehe die Referenz am Ende dieser Seite.

### Getaggte Pointer-Objekte

Einige Foundation-Klassen vermeiden Heap-Allokation, indem sie den Payload des Objekts direkt im Zeigerwert kodieren (tagged pointers). Die Erkennung unterscheidet sich je nach Plattform (z. B. das Most‑Significant-Bit auf arm64, das Least‑Significant auf x86_64 macOS). Getaggte Objekte haben kein reguläres `isa` im Speicher; die Runtime löst die Klasse aus den Tag-Bits auf. Beim Untersuchen beliebiger `id`-Werte:

- Verwende Runtime-APIs anstatt direkt am `isa`-Feld herumzupfen: `object_getClass(obj)` / `[obj class]`.
- In LLDB reicht `po (id)0xADDR`, um getaggte Pointer-Instanzen korrekt auszugeben, da die Runtime zur Bestimmung der Klasse herangezogen wird.

### Swift-Heap-Objekte und Metadaten

Pure Swift-Klassen sind ebenfalls Objekte mit einem Header, der auf Swift-Metadaten zeigt (nicht auf das Objective‑C-`isa`). Um laufende Swift-Prozesse zu introspektieren, ohne sie zu verändern, kannst du das Swift-Toolchain-Tool `swift-inspect` verwenden, das die Remote Mirror Library nutzt, um Runtime-Metadaten zu lesen:
```bash
# Xcode toolchain (or Swift.org toolchain) provides swift-inspect
swift-inspect dump-raw-metadata <pid-or-name>
swift-inspect dump-arrays <pid-or-name>
# On Darwin additionally:
swift-inspect dump-concurrency <pid-or-name>
```
Das ist sehr nützlich, um Swift-Heap-Objekte und Protokollkonformitäten zuzuordnen, beim reversing gemischter Swift/ObjC-Apps.

---

## Kurzreferenz zur Laufzeit-Inspektion (LLDB / Frida)

### LLDB

- Objekt oder Klasse aus einem rohen Zeiger ausgeben:
```lldb
(lldb) expr -l objc++ -O -- (id)0x0000000101234560
(lldb) expr -l objc++ -O -- (Class)object_getClass((id)0x0000000101234560)
```
- Objective‑C-Klasse aus einem Zeiger auf das `self` einer Objektmethode in einem Breakpoint inspizieren:
```lldb
(lldb) br se -n '-[NSFileManager fileExistsAtPath:]'
(lldb) r
... breakpoint hit ...
(lldb) po (id)$x0                 # self
(lldb) expr -l objc++ -O -- (Class)object_getClass((id)$x0)
```
- Dump sections that carry Objective‑C metadata (Hinweis: viele befinden sich jetzt in `__DATA_CONST` / `__AUTH_CONST`):
```lldb
(lldb) image dump section --section __DATA_CONST.__objc_classlist
(lldb) image dump section --section __DATA_CONST.__objc_selrefs
(lldb) image dump section --section __AUTH_CONST.__auth_got
```
- Lese den Speicher eines bekannten Klassenobjekts, um beim reversing von method lists zu `class_ro_t` / `class_rw_t` zu pivoten:
```lldb
(lldb) image lookup -r -n _OBJC_CLASS_$_NSFileManager
(lldb) memory read -fx -s8 0xADDRESS_OF_CLASS_OBJECT
```
### Frida (Objective‑C und Swift)

Frida bietet hochstufige Laufzeit‑Brücken, die sehr nützlich sind, um Live‑Objekte ohne Symbole zu entdecken und zu instrumentieren:

- Klassen und Methoden aufzählen, tatsächliche Klassennamen zur Laufzeit auflösen und Objective‑C selectors abfangen:
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
- Swift bridge: Swift-Typen auflisten und mit Swift-Instanzen interagieren (erfordert aktuelle Frida; sehr nützlich auf Apple Silicon-Zielen).

---

## Referenzen

- Clang/LLVM: Pointer Authentication und die `<ptrauth.h>` intrinsics (arm64e ABI). https://clang.llvm.org/docs/PointerAuthentication.html
- Apple objc runtime Header (tagged pointers, non‑pointer `isa`, etc.) z. B. `objc-object.h`. https://opensource.apple.com/source/objc4/objc4-818.2/runtime/objc-object.h.auto.html

{{#include ../../../banners/hacktricks-training.md}}
