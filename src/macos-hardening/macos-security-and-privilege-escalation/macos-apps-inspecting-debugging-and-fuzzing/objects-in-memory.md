# Obiekty w pamięci

{{#include ../../../banners/hacktricks-training.md}}

## CFRuntimeClass

Obiekty CF* pochodzą z CoreFoundation, które udostępnia ponad 50 klas obiektów, takich jak `CFString`, `CFNumber` czy `CFAllocator`.

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

### Używane sekcje pamięci

Większość danych używanych przez Objective-C runtime zmienia się podczas wykonywania, dlatego wykorzystuje on wiele sekcji z rodziny segmentów Mach-O `__DATA` w pamięci. Historycznie obejmowały one:

- `__objc_msgrefs` (`message_ref_t`): Referencje wiadomości
- `__objc_ivar` (`ivar`): Zmienne instancji
- `__objc_data` (`...`): Dane zmienne
- `__objc_classrefs` (`Class`): Referencje klas
- `__objc_superrefs` (`Class`): Referencje klas nadrzędnych
- `__objc_protorefs` (`protocol_t *`): Referencje protokołów
- `__objc_selrefs` (`SEL`): Referencje selectorów
- `__objc_const` (`...`): Dane klas tylko do odczytu i inne (miejmy nadzieję) stałe dane
- `__objc_imageinfo` (`version, flags`): Używane podczas ładowania obrazu: wersja obecnie wynosi `0`; flagi określają obsługę preoptymalizowanego GC itd.
- `__objc_protolist` (`protocol_t *`): Lista protokołów
- `__objc_nlcatlist` (`category_t`): Wskaźnik do Non-Lazy Categories zdefiniowanych w tym pliku binarnym
- `__objc_catlist` (`category_t`): Wskaźnik do Categories zdefiniowanych w tym pliku binarnym
- `__objc_nlclslist` (`classref_t`): Wskaźnik do Non-Lazy klas Objective-C zdefiniowanych w tym pliku binarnym
- `__objc_classlist` (`classref_t`): Wskaźniki do wszystkich klas Objective-C zdefiniowanych w tym pliku binarnym

Wykorzystuje także kilka sekcji w segmencie `__TEXT` do przechowywania stałych:

- `__objc_methname` (C‑String): Nazwy metod
- `__objc_classname` (C‑String): Nazwy klas
- `__objc_methtype` (C‑String): Typy metod

Nowoczesne macOS/iOS (szczególnie na Apple Silicon) umieszczają także metadane Objective-C/Swift w:

- `__DATA_CONST`: Niezmienne metadane Objective-C, które mogą być współdzielone między procesami w trybie tylko do odczytu (na przykład wiele list `__objc_*` znajduje się obecnie tutaj).
- `__AUTH` / `__AUTH_CONST`: Segmenty zawierające wskaźniki, które muszą zostać uwierzytelnione podczas ładowania lub użycia na arm64e (Pointer Authentication). W `__AUTH_CONST` zobaczysz także `__auth_got` zamiast używanych wcześniej wyłącznie `__la_symbol_ptr`/`__got`. Podczas instrumentowania lub hookowania pamiętaj o uwzględnieniu zarówno wpisów `__got`, jak i `__auth_got` we współczesnych plikach binarnych.

Informacje na temat preoptymalizacji dyld (np. ujednolicania selectorów oraz wstępnego obliczania klas/protokołów) i powodów, dla których wiele z tych sekcji jest „już poprawionych” pochodząc ze shared cache, znajdziesz w źródłach Apple `objc-opt` oraz notatkach dotyczących dyld shared cache. Ma to wpływ na to, gdzie i w jaki sposób można patchować metadane w runtime.

{{#ref}}
../macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.md
{{#endref}}

### Kodowanie typów

Objective-C używa manglingu do kodowania typów selectorów i zmiennych prostych oraz złożonych:

- Typy prymitywne używają pierwszej litery nazwy typu: `i` dla `int`, `c` dla `char`, `l` dla `long`... W przypadku typów bez znaku używana jest wielka litera (`L` dla `unsigned long`).
- Inne typy danych używają innych liter lub symboli, np. `q` dla `long long`, `b` dla bitfields, `B` dla booleanów, `#` dla klas, `@` dla `id`, `*` dla `char *`, `^` dla wskaźników ogólnych oraz `?` dla typu niezdefiniowanego.
- Tablice, struktury i unie używają odpowiednio `[`, `{` i `(`.

#### Przykładowa deklaracja metody
```objectivec
- (NSString *)processString:(id)input withOptions:(char *)options andError:(id)error;
```
Selektorem byłoby `processString:withOptions:andError:`

#### Kodowanie typów

- `id` jest kodowane jako `@`
- `char *` jest kodowane jako `*`

Pełne kodowanie typów dla metody to:
```less
@24@0:8@16*20^@24
```
#### Szczegółowy opis

1. Typ zwracany (`NSString *`): kodowany jako `@`, długość 24
2. `self` (instancja obiektu): kodowane jako `@`, z przesunięciem 0
3. `_cmd` (selector): kodowany jako `:`, z przesunięciem 8
4. Pierwszy argument (`char * input`): kodowany jako `*`, z przesunięciem 16
5. Drugi argument (`NSDictionary * options`): kodowany jako `@`, z przesunięciem 20
6. Trzeci argument (`NSError ** error`): kodowany jako `^@`, z przesunięciem 24

Mając selector + encoding, możesz odtworzyć metodę.

### Klasy

Klasy w Objective-C są strukturami C z właściwościami, wskaźnikami do metod itd. Strukturę `objc_class` można znaleźć w [**kodzie źródłowym**](https://opensource.apple.com/source/objc4/objc4-756.2/runtime/objc-runtime-new.h.auto.html):
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
Ta klasa używa niektórych bitów pola `isa` do wskazywania informacji o klasie.

Następnie struktura zawiera wskaźnik do struktury `class_ro_t` przechowywanej na dysku, która zawiera atrybuty klasy, takie jak jej nazwa, metody bazowe, właściwości i zmienne instancji. W czasie działania używana jest dodatkowa struktura `class_rw_t`, zawierająca wskaźniki, które mogą być modyfikowane, takie jak metody, protokoły i właściwości.

{{#ref}}
../macos-basic-objective-c.md
{{#endref}}

---

## Współczesne reprezentacje obiektów w pamięci (arm64e, tagged pointers, Swift)

### Non-pointer `isa` i Pointer Authentication (arm64e)

Na Apple Silicon i w nowszych runtime’ach Objective-C `isa` nie zawsze jest surowym wskaźnikiem klasy. Na arm64e jest to spakowana struktura, która może również zawierać Pointer Authentication Code (PAC). W zależności od platformy może ona zawierać pola takie jak `nonpointer`, `has_assoc`, `weakly_referenced`, `extra_rc` oraz sam wskaźnik klasy (przesunięty lub podpisany). Oznacza to, że bezpośrednie wyłuskanie pierwszych 8 bajtów obiektu Objective-C nie zawsze zwróci prawidłowy wskaźnik `Class`.<sup>[[2]](#references)</sup>

Praktyczne uwagi dotyczące debugowania na arm64e:

- LLDB zazwyczaj usunie dla Ciebie bity PAC podczas wyświetlania obiektów Objective-C za pomocą `po`, ale podczas pracy z surowymi wskaźnikami może być konieczne ręczne usunięcie uwierzytelniania:

```lldb
(lldb) expr -l objc++ -- #include <ptrauth.h>
(lldb) expr -l objc++ -- void *raw = ptrauth_strip((void*)0x000000016f123abc, ptrauth_key_asda);
(lldb) expr -l objc++ -O -- (Class)object_getClass((id)raw)
```

- Wiele wskaźników funkcji/danych w Mach-O znajduje się w `__AUTH`/`__AUTH_CONST` i przed użyciem wymaga uwierzytelnienia. Jeśli wykonujesz interposing lub re-binding (np. w stylu fishhook), upewnij się, że obsługujesz również `__auth_got`, oprócz starszego `__got`.

Szczegółowe omówienie gwarancji języka/ABI oraz intrinsiców `<ptrauth.h>` dostępnych w Clang/LLVM znajdziesz w odnośniku na końcu tej strony.<sup>[[1]](#references)</sup>

### Obiekty tagged pointer

Niektóre klasy Foundation unikają alokacji na heapie, kodując payload obiektu bezpośrednio w wartości wskaźnika (tagged pointers). Sposób wykrywania różni się w zależności od platformy (np. najbardziej znaczący bit na arm64, najmniej znaczący na x86_64 macOS). Obiekty tagged nie mają zwykłego `isa` przechowywanego w pamięci; runtime ustala klasę na podstawie bitów tagu.<sup>[[2]](#references)</sup> Podczas analizowania dowolnych wartości `id`:

- Używaj runtime API zamiast odczytywać pole `isa`: `object_getClass(obj)` / `[obj class]`.
- W LLDB samo `po (id)0xADDR` prawidłowo wyświetli instancje tagged pointer, ponieważ runtime jest używany do ustalenia klasy.

### Obiekty heap Swift i metadata

Czyste klasy Swift również są obiektami z nagłówkiem wskazującym na metadata Swift (a nie na `isa` Objective-C). Aby przeprowadzać introspekcję działających procesów Swift bez ich modyfikowania, możesz użyć `swift-inspect` z toolchaina Swift, który wykorzystuje bibliotekę Remote Mirror do odczytu runtime metadata:
```bash
# Xcode toolchain (or Swift.org toolchain) provides swift-inspect
swift-inspect dump-raw-metadata <pid-or-name>
swift-inspect dump-arrays <pid-or-name>
# On Darwin additionally:
swift-inspect dump-concurrency <pid-or-name>
```
Jest to bardzo przydatne do mapowania obiektów na stercie Swift i zgodności z protokołami podczas reverse engineeringu aplikacji łączących Swift i ObjC.

---

## Ściągawka z inspekcji runtime (LLDB / Frida)

### LLDB

- Wyświetlenie obiektu lub klasy ze wskaźnika raw:
```lldb
(lldb) expr -l objc++ -O -- (id)0x0000000101234560
(lldb) expr -l objc++ -O -- (Class)object_getClass((id)0x0000000101234560)
```
- Zbadaj klasę Objective‑C na podstawie wskaźnika do `self` metody obiektu w punkcie przerwania:
```lldb
(lldb) br se -n '-[NSFileManager fileExistsAtPath:]'
(lldb) r
... breakpoint hit ...
(lldb) po (id)$x0                 # self
(lldb) expr -l objc++ -O -- (Class)object_getClass((id)$x0)
```
- Zrzuć sekcje zawierające metadane Objective-C (uwaga: wiele z nich znajduje się teraz w `__DATA_CONST` / `__AUTH_CONST`):
```lldb
(lldb) image dump section --section __DATA_CONST.__objc_classlist
(lldb) image dump section --section __DATA_CONST.__objc_selrefs
(lldb) image dump section --section __AUTH_CONST.__auth_got
```
- Odczytaj pamięć znanego obiektu klasy, aby przejść do `class_ro_t` / `class_rw_t` podczas reverse engineeringu list metod:
```lldb
(lldb) image lookup -r -n _OBJC_CLASS_$_NSFileManager
(lldb) memory read -fx -s8 0xADDRESS_OF_CLASS_OBJECT
```
### Frida (Objective-C i Swift)

Frida udostępnia wysokopoziomowe mosty runtime, które są bardzo przydatne do wykrywania i instrumentowania aktywnych obiektów bez symboli:

- Wyliczaj klasy i metody, rozwiązuj rzeczywiste nazwy klas w runtime oraz przechwytuj selektory Objective-C:
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
- Swift bridge: wyliczanie typów Swift i interakcja z instancjami Swift (wymaga recent Frida; bardzo przydatne w przypadku targets z Apple Silicon).

---

## Referencje


- [1] [Clang/LLVM: Pointer Authentication and the ptrauth.h intrinsics (arm64e ABI)](https://clang.llvm.org/docs/PointerAuthentication.html)
- [2] [Apple objc runtime headers - objc-object.h (tagged pointers, non‑pointer isa, etc.)](https://opensource.apple.com/source/objc4/objc4-818.2/runtime/objc-object.h.auto.html)

{{#include ../../../banners/hacktricks-training.md}}
