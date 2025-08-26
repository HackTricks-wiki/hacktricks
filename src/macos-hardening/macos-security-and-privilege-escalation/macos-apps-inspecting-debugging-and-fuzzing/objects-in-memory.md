# Obiekty w pamięci

{{#include ../../../banners/hacktricks-training.md}}

## CFRuntimeClass

Obiekty CF* pochodzą z CoreFoundation, które dostarcza ponad 50 klas obiektów, takich jak `CFString`, `CFNumber` czy `CFAllocator`.

Wszystkie te klasy są instancjami klasy `CFRuntimeClass`, która po wywołaniu zwraca indeks do `__CFRuntimeClassTable`. CFRuntimeClass jest zdefiniowana w [**CFRuntime.h**](https://opensource.apple.com/source/CF/CF-1153.18/CFRuntime.h.auto.html):
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

Większość danych używanych przez runtime Objective‑C zmienia się podczas wykonywania, dlatego w pamięci używa kilku sekcji z rodziny segmentów Mach‑O `__DATA`. Historycznie obejmowały one:

- `__objc_msgrefs` (`message_ref_t`): Referencje do wiadomości
- `__objc_ivar` (`ivar`): Zmienne instancji
- `__objc_data` (`...`): Dane modyfikowalne
- `__objc_classrefs` (`Class`): Referencje do klas
- `__objc_superrefs` (`Class`): Referencje do klas bazowych
- `__objc_protorefs` (`protocol_t *`): Referencje protokołów
- `__objc_selrefs` (`SEL`): Referencje selektorów
- `__objc_const` (`...`): Dane klas tylko do odczytu i inne (miejmy nadzieję) stałe dane
- `__objc_imageinfo` (`version, flags`): Używane podczas ładowania obrazu: Wersja obecnie `0`; Flagi określają wsparcie preoptymalizowanego GC itp.
- `__objc_protolist` (`protocol_t *`): Lista protokołów
- `__objc_nlcatlist` (`category_t`): Wskaźnik do Non-Lazy Categories zdefiniowanych w tym pliku binarnym
- `__objc_catlist` (`category_t`): Wskaźnik do Categories zdefiniowanych w tym pliku binarnym
- `__objc_nlclslist` (`classref_t`): Wskaźnik do Non-Lazy klas Objective‑C zdefiniowanych w tym pliku binarnym
- `__objc_classlist` (`classref_t`): Wskaźniki do wszystkich klas Objective‑C zdefiniowanych w tym pliku binarnym

Wykorzystuje też kilka sekcji w segmencie `__TEXT` do przechowywania stałych:

- `__objc_methname` (C‑String): Nazwy metod
- `__objc_classname` (C‑String): Nazwy klas
- `__objc_methtype` (C‑String): Typy metod

Nowoczesne macOS/iOS (zwłaszcza na Apple Silicon) umieszczają także metadane Objective‑C/Swift w:

- `__DATA_CONST`: niemutowalne metadane Objective‑C, które mogą być współdzielone jako tylko do odczytu między procesami (np. wiele list `__objc_*` znajduje się teraz tutaj).
- `__AUTH` / `__AUTH_CONST`: segmenty zawierające wskaźniki, które muszą być uwierzytelnione podczas ładowania lub użycia na arm64e (Pointer Authentication). Zobaczysz też `__auth_got` w `__AUTH_CONST` zamiast jedynie legacy `__la_symbol_ptr`/`__got`. Podczas instrumentacji lub hookowania pamiętaj, aby uwzględnić zarówno wpisy `__got`, jak i `__auth_got` w nowoczesnych binariach.

Aby poznać tło dyld pre‑optimization (np. selector uniquing i class/protocol precomputation) oraz dowiedzieć się, dlaczego wiele z tych sekcji jest "already fixed up" przy ładowaniu ze shared cache, sprawdź źródła Apple `objc-opt` i notatki dotyczące dyld shared cache. Ma to wpływ na to, gdzie i jak możesz patchować metadane w czasie wykonywania.

{{#ref}}
../macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.md
{{#endref}}

### Type Encoding

Objective‑C używa manglingu, aby zakodować typy selektorów i zmiennych, zarówno proste, jak i złożone:

- Typy proste używają pierwszej litery typu: `i` dla `int`, `c` dla `char`, `l` dla `long`... i używają wielkiej litery, gdy typ jest unsigned (`L` dla `unsigned long`).
- Inne typy danych używają innych liter lub symboli, np. `q` dla `long long`, `b` dla bitfieldów, `B` dla booleanów, `#` dla klas, `@` dla `id`, `*` dla `char *`, `^` dla wskaźników ogólnych i `?` dla nieokreślonego.
- Tablice, struktury i unie używają odpowiednio `[`, `{` i `(`.

#### Example Method Declaration
```objectivec
- (NSString *)processString:(id)input withOptions:(char *)options andError:(id)error;
```
Selektor będzie `processString:withOptions:andError:`

#### Kodowanie typów

- `id` jest kodowane jako `@`
- `char *` jest kodowane jako `*`

Pełne kodowanie typów dla metody to:
```less
@24@0:8@16*20^@24
```
#### Szczegółowy podział

1. Typ zwracany (`NSString *`): Zakodowany jako `@` o długości 24
2. `self` (instancja obiektu): Zakodowany jako `@`, na przesunięciu 0
3. `_cmd` (selektor): Zakodowany jako `:`, na przesunięciu 8
4. Pierwszy argument (`char * input`): Zakodowany jako `*`, na przesunięciu 16
5. Drugi argument (`NSDictionary * options`): Zakodowany jako `@`, na przesunięciu 20
6. Trzeci argument (`NSError ** error`): Zakodowany jako `^@`, na przesunięciu 24

Dzięki selektorowi + kodowaniu możesz zrekonstruować metodę.

### Klasy

Klasy w Objective‑C są strukturami C z właściwościami, wskaźnikami do metod itd. Można znaleźć strukturę `objc_class` w [**source code**](https://opensource.apple.com/source/objc4/objc4-756.2/runtime/objc-runtime-new.h.auto.html):
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
Ta klasa używa niektórych bitów pola `isa` do zakodowania informacji o klasie.

Następnie struktura zawiera wskaźnik do struktury `class_ro_t` przechowywanej na dysku, która zawiera atrybuty klasy, takie jak jej nazwa, metody bazowe, właściwości i zmienne instancji. W czasie działania używana jest dodatkowa struktura `class_rw_t`, zawierająca wskaźniki które mogą być modyfikowane, np. metody, protokoły, właściwości.

{{#ref}}
../macos-basic-objective-c.md
{{#endref}}

---

## Nowoczesne reprezentacje obiektów w pamięci (arm64e, tagged pointers, Swift)

### `isa` nie będący wskaźnikiem i uwierzytelnianie wskaźników (arm64e)

Na Apple Silicon i w nowszych runtime'ach Objective‑C `isa` nie zawsze jest zwykłym wskaźnikiem klasy. Na arm64e jest to spakowana struktura, która może także zawierać Pointer Authentication Code (PAC). W zależności od platformy może zawierać pola takie jak `nonpointer`, `has_assoc`, `weakly_referenced`, `extra_rc` oraz sam wskaźnik klasy (przesunięty lub podpisany). Oznacza to, że bezmyślne dereferencjonowanie pierwszych 8 bajtów obiektu Objective‑C nie zawsze zwróci prawidłowy wskaźnik `Class`.

Praktyczne uwagi przy debugowaniu na arm64e:

- LLDB zwykle usunie bity PAC dla Ciebie podczas drukowania obiektów Objective‑C za pomocą `po`, ale przy pracy z surowymi wskaźnikami może być konieczne ręczne usunięcie uwierzytelnienia:

```lldb
(lldb) expr -l objc++ -- #include <ptrauth.h>
(lldb) expr -l objc++ -- void *raw = ptrauth_strip((void*)0x000000016f123abc, ptrauth_key_asda);
(lldb) expr -l objc++ -O -- (Class)object_getClass((id)raw)
```

- Wiele wskaźników funkcyjnych/danych w Mach‑O znajduje się w `__AUTH`/`__AUTH_CONST` i wymaga uwierzytelnienia przed użyciem. Jeśli przechwytujesz lub przebindowujesz (np. w stylu fishhook), upewnij się, że obsłużysz także `__auth_got` oprócz starszego `__got`.

Aby zgłębić gwarancje językowe/ABI oraz intrinsics z `<ptrauth.h>` dostępne w Clang/LLVM, zobacz odnośnik na końcu tej strony.

### Obiekty tagged pointer

Niektóre klasy Foundation unikają alokacji na stercie przez zakodowanie ładunku obiektu bezpośrednio w wartości wskaźnika (tagged pointers). Wykrywanie różni się w zależności od platformy (np. bit najbardziej znaczący na arm64, najmniej znaczący na x86_64 macOS). Obiekty tagged nie mają zwykłego `isa` przechowywanego w pamięci; runtime rozpoznaje klasę na podstawie bitów znacznika. Przy badaniu dowolnych wartości `id`:

- Używaj API runtime zamiast manipulować polem `isa`: `object_getClass(obj)` / `[obj class]`.
- W LLDB wystarczy `po (id)0xADDR`, aby poprawnie wydrukować instancje tagged pointer, ponieważ runtime jest konsultowany w celu rozpoznania klasy.

### Obiekty Swift na stercie i metadane

Czyste klasy Swift również są obiektami z nagłówkiem wskazującym na metadane Swift (nie Objective‑C `isa`). Aby introspektować działające procesy Swift bez ich modyfikowania, możesz użyć narzędzia toolchain Swift `swift-inspect`, które wykorzystuje bibliotekę Remote Mirror do odczytu metadanych runtime:
```bash
# Xcode toolchain (or Swift.org toolchain) provides swift-inspect
swift-inspect dump-raw-metadata <pid-or-name>
swift-inspect dump-arrays <pid-or-name>
# On Darwin additionally:
swift-inspect dump-concurrency <pid-or-name>
```
Jest to bardzo przydatne do mapowania obiektów sterty Swift i zgodności z protokołami podczas analizy wstecznej mieszanych aplikacji Swift/ObjC.

---

## Skrócona ściąga do inspekcji czasu wykonywania (LLDB / Frida)

### LLDB

- Wyświetl obiekt lub klasę z surowego wskaźnika:
```lldb
(lldb) expr -l objc++ -O -- (id)0x0000000101234560
(lldb) expr -l objc++ -O -- (Class)object_getClass((id)0x0000000101234560)
```
- Zbadaj Objective‑C class z wskaźnika do `self` metody obiektu w breakpoint:
```lldb
(lldb) br se -n '-[NSFileManager fileExistsAtPath:]'
(lldb) r
... breakpoint hit ...
(lldb) po (id)$x0                 # self
(lldb) expr -l objc++ -O -- (Class)object_getClass((id)$x0)
```
- Zrzucaj sekcje, które zawierają metadane Objective‑C (uwaga: wiele z nich znajduje się teraz w `__DATA_CONST` / `__AUTH_CONST`):
```lldb
(lldb) image dump section --section __DATA_CONST.__objc_classlist
(lldb) image dump section --section __DATA_CONST.__objc_selrefs
(lldb) image dump section --section __AUTH_CONST.__auth_got
```
- Odczytaj pamięć znanego obiektu klasy, aby wykonać pivot do `class_ro_t` / `class_rw_t` podczas odwracania list metod:
```lldb
(lldb) image lookup -r -n _OBJC_CLASS_$_NSFileManager
(lldb) memory read -fx -s8 0xADDRESS_OF_CLASS_OBJECT
```
### Frida (Objective‑C and Swift)

Frida udostępnia wysokopoziomowe mosty runtime, które są bardzo przydatne do odkrywania i instrumentowania działających obiektów bez symboli:

- Wyliczanie klas i metod, rozpoznawanie rzeczywistych nazw klas w czasie wykonywania oraz przechwytywanie Objective‑C selectors:
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
- Swift bridge: wylicza typy Swift i umożliwia interakcję z instancjami Swift (wymaga nowszej wersji Frida; bardzo przydatne na urządzeniach Apple Silicon).

---

## Odniesienia

- Clang/LLVM: Pointer Authentication i intrinsics z `<ptrauth.h>` (arm64e ABI). https://clang.llvm.org/docs/PointerAuthentication.html
- Nagłówki runtime objc Apple (tagged pointers, non‑pointer `isa`, etc.) np. `objc-object.h`. https://opensource.apple.com/source/objc4/objc4-818.2/runtime/objc-object.h.auto.html

{{#include ../../../banners/hacktricks-training.md}}
