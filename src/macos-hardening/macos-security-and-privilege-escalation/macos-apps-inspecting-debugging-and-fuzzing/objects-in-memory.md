# Bellekteki nesneler

{{#include ../../../banners/hacktricks-training.md}}

## CFRuntimeClass

CF* nesneleri, `CFString`, `CFNumber` veya `CFAllocator` gibi 50'den fazla nesne sınıfı sağlayan CoreFoundation'dan gelir.

Tüm bu sınıflar, çağrıldığında `__CFRuntimeClassTable` tablosuna bir indeks döndüren `CFRuntimeClass` sınıfının örnekleridir. CFRuntimeClass, [**CFRuntime.h**](https://opensource.apple.com/source/CF/CF-1153.18/CFRuntime.h.auto.html) içinde tanımlanmıştır:
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

### Kullanılan memory bölümleri

Objective-C runtime tarafından kullanılan verilerin çoğu execution sırasında değişir; bu nedenle memory içinde Mach-O `__DATA` segment ailesinden çeşitli bölümleri kullanır. Tarihsel olarak bunlar şunlardı:

- `__objc_msgrefs` (`message_ref_t`): Message referansları
- `__objc_ivar` (`ivar`): Instance variable'lar
- `__objc_data` (`...`): Değiştirilebilir veriler
- `__objc_classrefs` (`Class`): Class referansları
- `__objc_superrefs` (`Class`): Superclass referansları
- `__objc_protorefs` (`protocol_t *`): Protocol referansları
- `__objc_selrefs` (`SEL`): Selector referansları
- `__objc_const` (`...`): Class r/o verileri ve diğer (umarız) sabit veriler
- `__objc_imageinfo` (`version, flags`): Image load sırasında kullanılır: Version şu anda `0`; Flags, preoptimized GC desteğini vb. belirtir.
- `__objc_protolist` (`protocol_t *`): Protocol listesi
- `__objc_nlcatlist` (`category_t`): Bu binary içinde tanımlanan Non-Lazy Categories işaretçisi
- `__objc_catlist` (`category_t`): Bu binary içinde tanımlanan Categories işaretçisi
- `__objc_nlclslist` (`classref_t`): Bu binary içinde tanımlanan Non-Lazy Objective-C class'larının işaretçisi
- `__objc_classlist` (`classref_t`): Bu binary içinde tanımlanan tüm Objective-C class'larının işaretçileri

Ayrıca sabitleri depolamak için `__TEXT` segmentinde birkaç bölüm kullanır:

- `__objc_methname` (C-String): Method adları
- `__objc_classname` (C-String): Class adları
- `__objc_methtype` (C-String): Method type'ları

Modern macOS/iOS (özellikle Apple Silicon üzerinde) Objective-C/Swift metadata'sını şu bölümlere de yerleştirir:

- `__DATA_CONST`: Process'ler arasında read-only olarak paylaşılabilen immutable Objective-C metadata'sı (örneğin birçok `__objc_*` listesi artık burada bulunur).
- `__AUTH` / `__AUTH_CONST`: arm64e üzerinde load veya kullanım sırasında authenticate edilmesi gereken işaretçileri içeren segment'ler (Pointer Authentication). Modern binary'lerde yalnızca legacy `__la_symbol_ptr`/`__got` yerine `__AUTH_CONST` içinde `__auth_got` da görürsünüz. Instrumentation veya hooking sırasında modern binary'lerde hem `__got` hem de `__auth_got` entry'lerini hesaba katmayı unutmayın.

dyld pre-optimization (örneğin selector uniquing ve class/protocol precomputation) ve shared cache'ten gelen bu bölümlerin çoğunun neden "zaten fixed up" olduğunu anlamak için Apple'ın `objc-opt` kaynaklarını ve dyld shared cache notlarını inceleyin. Bu durum, runtime sırasında metadata'yı nerede ve nasıl patch edebileceğinizi etkiler.

{{#ref}}
../macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.md
{{#endref}}

### Type Encoding

Objective-C, basit ve karmaşık type'ların selector ve variable type'larını encode etmek için mangling kullanır:

- Primitive type'lar, type'ın ilk harfini kullanır: `int` için `i`, `char` için `c`, `long` için `l`... unsigned olması durumunda büyük harf kullanılır (`unsigned long` için `L`).
- Diğer data type'ları `long long` için `q`, bitfield'lar için `b`, boolean'lar için `B`, class'lar için `#`, `id` için `@`, `char *` için `*`, generic pointer'lar için `^` ve undefined için `?` gibi başka harf veya semboller kullanır.
- Array'ler, structure'lar ve union'lar sırasıyla `[`, `{` ve `(` kullanır.

#### Örnek Method Declaration
```objectivec
- (NSString *)processString:(id)input withOptions:(char *)options andError:(id)error;
```
Selector `processString:withOptions:andError:` olur.

#### Type Encoding

- `id`, `@` olarak encode edilir
- `char *`, `*` olarak encode edilir

Method için tam type encoding şöyledir:
```less
@24@0:8@16*20^@24
```
#### Ayrıntılı Döküm

1. Dönüş Türü (`NSString *`): Uzunluğu 24 olan `@` olarak kodlanır
2. `self` (nesne örneği): `@` olarak kodlanır, offset 0
3. `_cmd` (selector): `:` olarak kodlanır, offset 8
4. İlk bağımsız değişken (`char * input`): `*` olarak kodlanır, offset 16
5. İkinci bağımsız değişken (`NSDictionary * options`): `@` olarak kodlanır, offset 20
6. Üçüncü bağımsız değişken (`NSError ** error`): `^@` olarak kodlanır, offset 24

Selector ve encoding ile method'u yeniden oluşturabilirsiniz.

### Sınıflar

Objective-C'deki sınıflar; özellikler, method pointer'ları vb. içeren C struct'larıdır. `objc_class` struct'ını [**kaynak kodunda**](https://opensource.apple.com/source/objc4/objc4-756.2/runtime/objc-runtime-new.h.auto.html) bulmak mümkündür:
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
Bu class, class hakkında bilgi belirtmek için `isa` alanının bazı bitlerini kullanır.

Ardından struct, diskte depolanan ve class'ın adı, temel methods, properties ve instance variables gibi özniteliklerini içeren `class_ro_t` struct'ına bir pointer barındırır. Runtime sırasında, methods, protocols ve properties gibi değiştirilebilen pointer'ları içeren ek bir `class_rw_t` yapısı kullanılır.

{{#ref}}
../macos-basic-objective-c.md
{{#endref}}

---

## Bellekteki modern object gösterimleri (arm64e, tagged pointers, Swift)

### Non-pointer `isa` ve Pointer Authentication (arm64e)

Apple Silicon ve güncel runtime'larda Objective-C `isa`, her zaman ham bir class pointer'ı değildir. arm64e üzerinde, Pointer Authentication Code (PAC) da taşıyabilen packed bir yapıdır. Platforma bağlı olarak `nonpointer`, `has_assoc`, `weakly_referenced`, `extra_rc` ve class pointer'ın kendisi (shift edilmiş veya signed) gibi alanlar içerebilir. Bu nedenle bir Objective-C object'inin ilk 8 byte'ını körü körüne dereference etmek her zaman geçerli bir `Class` pointer'ı elde edilmesini sağlamaz.<sup>[[2]](#references)</sup>

arm64e üzerinde debugging yaparken pratik notlar:

- Objective-C object'lerini `po` ile yazdırırken LLDB genellikle PAC bitlerini sizin için temizler; ancak raw pointer'larla çalışırken authentication'ı manuel olarak temizlemeniz gerekebilir:

```lldb
(lldb) expr -l objc++ -- #include <ptrauth.h>
(lldb) expr -l objc++ -- void *raw = ptrauth_strip((void*)0x000000016f123abc, ptrauth_key_asda);
(lldb) expr -l objc++ -O -- (Class)object_getClass((id)raw)
```

- Mach-O içindeki birçok function/data pointer `__AUTH`/`__AUTH_CONST` içinde bulunur ve kullanılmadan önce authentication gerektirir. Interposing veya re-binding yapıyorsanız (ör. fishhook-style), legacy `__got`'a ek olarak `__auth_got` desteğini de sağladığınızdan emin olun.

Dil/ABI garantileri ve Clang/LLVM tarafından sunulan `<ptrauth.h>` intrinsics hakkında ayrıntılı bilgi için bu sayfanın sonundaki reference'a bakın.<sup>[[1]](#references)</sup>

### Tagged pointer object'leri

Bazı Foundation class'ları, object'in payload'ını doğrudan pointer değerinin içinde encode ederek heap allocation'dan kaçınır (tagged pointers). Detection platforma göre değişir (ör. arm64 üzerinde most-significant bit, x86_64 macOS üzerinde least-significant bit). Tagged object'lerin memory'de normal bir `isa`'sı bulunmaz; runtime, class'ı tag bit'lerinden çözer.<sup>[[2]](#references)</sup> Rastgele `id` değerlerini inspect ederken:

- `isa` alanını doğrudan okumak yerine runtime API'lerini kullanın: `object_getClass(obj)` / `[obj class]`.
- LLDB'de `po (id)0xADDR` komutu, class'ı çözmek için runtime'a başvurduğundan tagged pointer instance'larını doğru şekilde yazdırır.

### Swift heap object'leri ve metadata

Pure Swift class'ları da Swift metadata'sına işaret eden bir header'a sahip object'lerdir (Objective-C `isa`'sı değil). Canlı Swift process'lerini değiştirmeden introspect etmek için, runtime metadata'sını okumak üzere Remote Mirror library'sini kullanan Swift toolchain'in `swift-inspect` aracını kullanabilirsiniz:
```bash
# Xcode toolchain (or Swift.org toolchain) provides swift-inspect
swift-inspect dump-raw-metadata <pid-or-name>
swift-inspect dump-arrays <pid-or-name>
# On Darwin additionally:
swift-inspect dump-concurrency <pid-or-name>
```
Bu, mixed Swift/ObjC uygulamalarını reverse ederken Swift heap nesnelerini ve protocol uyumluluklarını eşlemek için çok kullanışlıdır.

---

## Runtime inspection hızlı başvuru (LLDB / Frida)

### LLDB

- raw pointer üzerinden nesne veya sınıfı yazdır:
```lldb
(lldb) expr -l objc++ -O -- (id)0x0000000101234560
(lldb) expr -l objc++ -O -- (Class)object_getClass((id)0x0000000101234560)
```
- Bir kesme noktasında, bir nesne metodunun `self` işaretçisinden Objective-C sınıfını inceleyin:
```lldb
(lldb) br se -n '-[NSFileManager fileExistsAtPath:]'
(lldb) r
... breakpoint hit ...
(lldb) po (id)$x0                 # self
(lldb) expr -l objc++ -O -- (Class)object_getClass((id)$x0)
```
- Objective-C metadata taşıyan section'ları dump'layın (not: birçoğu artık `__DATA_CONST` / `__AUTH_CONST` içinde):
```lldb
(lldb) image dump section --section __DATA_CONST.__objc_classlist
(lldb) image dump section --section __DATA_CONST.__objc_selrefs
(lldb) image dump section --section __AUTH_CONST.__auth_got
```
- Method listelerini reverse ederken `class_ro_t` / `class_rw_t` öğelerine pivot yapmak için bilinen bir class nesnesinin memory'sini okuyun:
```lldb
(lldb) image lookup -r -n _OBJC_CLASS_$_NSFileManager
(lldb) memory read -fx -s8 0xADDRESS_OF_CLASS_OBJECT
```
### Frida (Objective‑C ve Swift)

Frida, symbols olmadan canlı nesneleri keşfetmek ve instrument etmek için oldukça kullanışlı olan üst düzey runtime bridge'leri sağlar:

- Sınıfları ve method'ları listeleyin, gerçek sınıf adlarını runtime'da çözümleyin ve Objective‑C selector'larını intercept edin:
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
- Swift bridge: Swift türlerini enumerate edin ve Swift instance'larıyla etkileşime geçin (güncel Frida gerektirir; Apple Silicon hedeflerinde çok kullanışlıdır).

---

## Referanslar

- [1] [Clang/LLVM: Pointer Authentication and the ptrauth.h intrinsics (arm64e ABI)](https://clang.llvm.org/docs/PointerAuthentication.html)
- [2] [Apple objc runtime headers - objc-object.h (tagged pointers, non‑pointer isa, etc.)](https://opensource.apple.com/source/objc4/objc4-818.2/runtime/objc-object.h.auto.html)

{{#include ../../../banners/hacktricks-training.md}}
