# Bellekteki nesneler

{{#include ../../../banners/hacktricks-training.md}}

## CFRuntimeClass

CF* nesneleri CoreFoundation'dan gelir; CoreFoundation `CFString`, `CFNumber` veya `CFAllocator` gibi 50'den fazla nesne sınıfı sağlar.

Tüm bu sınıflar `CFRuntimeClass` sınıfının örnekleridir; çağrıldığında `__CFRuntimeClassTable`'a bir indeks döndürür. CFRuntimeClass [**CFRuntime.h**](https://opensource.apple.com/source/CF/CF-1153.18/CFRuntime.h.auto.html) içinde tanımlıdır:
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

Objective‑C runtime tarafından kullanılan verilerin çoğu yürütme sırasında değişeceğinden, bellekte Mach‑O `__DATA` segment ailesinden bir dizi bölüm kullanılır. Tarihsel olarak bunlar şunlardı:

- `__objc_msgrefs` (`message_ref_t`): Mesaj referansları
- `__objc_ivar` (`ivar`): Örnek (instance) değişkenleri
- `__objc_data` (`...`): Değiştirilebilir veriler
- `__objc_classrefs` (`Class`): Sınıf referansları
- `__objc_superrefs` (`Class`): Süperclass referansları
- `__objc_protorefs` (`protocol_t *`): Protocol referansları
- `__objc_selrefs` (`SEL`): Selector referansları
- `__objc_const` (`...`): Sınıf salt okunur verisi ve diğer (umarım) sabit veriler
- `__objc_imageinfo` (`version, flags`): Image yüklenirken kullanılır: Versiyon şu anda `0`; Flags önceden optimize edilmiş GC desteğini vb. belirtir.
- `__objc_protolist` (`protocol_t *`): Protocol listesi
- `__objc_nlcatlist` (`category_t`): Bu binary içinde tanımlı Non-Lazy Categories'e işaretçi
- `__objc_catlist` (`category_t`): Bu binary içinde tanımlı Categories'e işaretçi
- `__objc_nlclslist` (`classref_t`): Bu binary içinde tanımlı Non-Lazy Objective‑C sınıflarına işaretçi
- `__objc_classlist` (`classref_t`): Bu binary içinde tanımlı tüm Objective‑C sınıflarına işaretçiler

Ayrıca sabitleri depolamak için `__TEXT` segmentinde birkaç bölüm kullanır:

- `__objc_methname` (C‑String): Metod isimleri
- `__objc_classname` (C‑String): Sınıf isimleri
- `__objc_methtype` (C‑String): Metod tipleri

Modern macOS/iOS (özellikle Apple Silicon’da) ayrıca Objective‑C/Swift meta verilerini şurada tutar:

- `__DATA_CONST`: işlemler arasında salt okunur olarak paylaşılabilecek değiştirilemez Objective‑C meta verileri (örneğin birçok `__objc_*` listesi artık burada bulunuyor).
- `__AUTH` / `__AUTH_CONST`: arm64e üzerinde yükleme veya kullanım zamanında kimlik doğrulanması gereken işaretçileri içeren segmentler (Pointer Authentication). Ayrıca legacy `__la_symbol_ptr`/`__got` yerine `__AUTH_CONST` içinde `__auth_got` göreceksiniz. instrumenting or hooking yaparken, modern ikilik dosyalardaki hem `__got` hem de `__auth_got` girdilerini hesaba katmayı unutmayın.

dyld ön‑optimizasyonu hakkında arka plan için (örn., selector uniquing ve class/protocol önhesaplama) ve neden bu bölümlerin birçoğunun shared cache'ten gelirken "zaten düzeltilmiş" olduğunu anlamak için Apple `objc-opt` kaynaklarına ve dyld shared cache notlarına bakın. Bu, çalışma zamanında meta verileri nerede ve nasıl yamalayabileceğinizi etkiler.

{{#ref}}
../macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.md
{{#endref}}

### Tip Kodlaması

Objective‑C, seçici ve değişken tiplerini (basit ve karmaşık olanları) kodlamak için mangling kullanır:

- İlkel (primitive) tipler tipin ilk harfini kullanır: `i` için `int`, `c` için `char`, `l` için `long`... ve işaretsiz ise büyük harf kullanılır (`L` için `unsigned long`).
- Diğer veri tipleri farklı harfler veya semboller kullanır; örneğin `q` için `long long`, `b` için bitfield'lar, `B` için boolean'lar, `#` sınıflar için, `@` `id` için, `*` `char *` için, `^` genel işaretçiler için ve `?` tanımsız için.
- Diziler, yapılar ve union'lar sırasıyla `[`, `{` ve `(` kullanır.

#### Örnek Metod Deklarasyonu
```objectivec
- (NSString *)processString:(id)input withOptions:(char *)options andError:(id)error;
```
Seçici şu olur `processString:withOptions:andError:`

#### Type Encoding

- `id` şu şekilde kodlanır: `@`
- `char *` şu şekilde kodlanır: `*`

Metot için tam tür kodlaması şudur:
```less
@24@0:8@16*20^@24
```
#### Detaylı Açılım

1. Return Type (`NSString *`): Uzunluğu 24 olan `@` olarak kodlanmış
2. `self` (object instance): `@` olarak kodlanmış, offset 0'da
3. `_cmd` (selector): `:` olarak kodlanmış, offset 8'de
4. First argument (`char * input`): `*` olarak kodlanmış, offset 16'da
5. Second argument (`NSDictionary * options`): `@` olarak kodlanmış, offset 20'de
6. Third argument (`NSError ** error`): `^@` olarak kodlanmış, offset 24'te

Selector + kodlama ile metodu yeniden oluşturabilirsiniz.

### Sınıflar

Objective‑C'deki sınıflar, özellikler, method pointers, vb. içeren C struct'larıdır. `objc_class` struct'ını [**source code**](https://opensource.apple.com/source/objc4/objc4-756.2/runtime/objc-runtime-new.h.auto.html) içinde bulmak mümkündür:
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

## Bellekte modern nesne temsil biçimleri (arm64e, tagged pointers, Swift)

### Non‑pointer `isa` ve Pointer Authentication (arm64e)

Apple Silicon ve yeni runtime'larda Objective‑C `isa` her zaman ham bir class pointer'ı değildir. arm64e üzerinde paketlenmiş bir yapı olup aynı zamanda Pointer Authentication Code (PAC) taşıyabilir. Platforma bağlı olarak `nonpointer`, `has_assoc`, `weakly_referenced`, `extra_rc` ve class pointer'ı (shifted veya signed) gibi alanlar içerebilir. Bu, bir Objective‑C nesnesinin ilk 8 baytını körü körüne dereference etmenin her zaman geçerli bir `Class` pointer'ı vermeyeceği anlamına gelir.

arm64e üzerinde debug yaparken pratik notlar:

- LLDB genellikle `po` ile Objective‑C nesnelerini yazdırırken PAC bitlerini sizin için temizler, ancak ham pointerlarla çalışırken authentication'ı elle temizlemeniz gerekebilir:

```lldb
(lldb) expr -l objc++ -- #include <ptrauth.h>
(lldb) expr -l objc++ -- void *raw = ptrauth_strip((void*)0x000000016f123abc, ptrauth_key_asda);
(lldb) expr -l objc++ -O -- (Class)object_getClass((id)raw)
```

- Birçok function/data pointer Mach‑O içinde `__AUTH`/`__AUTH_CONST` bölümlerinde yer alır ve kullanılmadan önce authentication gerektirir. Eğer interposing veya re‑binding (ör. fishhook‑style) yapıyorsanız, legacy `__got`'a ek olarak `__auth_got` ile de ilgilendiğinizden emin olun.

Dil/ABI garantileri ve Clang/LLVM'den erişilebilen `<ptrauth.h>` intrinsics hakkında derin bir inceleme için sayfa sonundaki referansa bakın.

### Tagged pointer nesneler

Bazı Foundation sınıfları, nesnenin payload'unu doğrudan pointer değeri içinde kodlayarak heap tahsisinden kaçınır (tagged pointers). Tespiti platforma göre değişir (örn. arm64'te en anlamlı bit, x86_64 macOS'ta en az anlamlı bit). Tagged nesnelerin bellekte normal bir `isa`'sı yoktur; runtime tag bitlerinden class'ı çözer. Rastgele `id` değerlerini incelerken:

- `isa` alanını karıştırmak yerine runtime API'lerini kullanın: `object_getClass(obj)` / `[obj class]`.
- LLDB'de, sadece `po (id)0xADDR` tagged pointer instance'larını doğru şekilde yazdırır çünkü class'ı çözmek için runtime'a başvurulur.

### Swift heap nesneleri ve metadata

Saf Swift sınıfları da Objective‑C `isa` değil, Swift metadata'sını işaret eden bir header'a sahip nesnelerdir. Canlı Swift proseslerini değiştirmeden introspect etmek için Swift toolchain'in `swift-inspect` aracını kullanabilirsiniz; bu araç runtime metadata'sını okumak için Remote Mirror kütüphanesini kullanır:
```bash
# Xcode toolchain (or Swift.org toolchain) provides swift-inspect
swift-inspect dump-raw-metadata <pid-or-name>
swift-inspect dump-arrays <pid-or-name>
# On Darwin additionally:
swift-inspect dump-concurrency <pid-or-name>
```
Bu, karışık Swift/ObjC uygulamalarını tersine mühendislik yaparken Swift heap nesnelerini ve protokol uygunluklarını haritalamak için çok kullanışlıdır.

---

## Çalışma zamanı inceleme kılavuzu (LLDB / Frida)

### LLDB

- Ham işaretçiden obje veya sınıfı yazdır:
```lldb
(lldb) expr -l objc++ -O -- (id)0x0000000101234560
(lldb) expr -l objc++ -O -- (Class)object_getClass((id)0x0000000101234560)
```
- Bir nesne metodunun `self` işaretçisinden Objective‑C class'ını breakpoint sırasında inceleyin:
```lldb
(lldb) br se -n '-[NSFileManager fileExistsAtPath:]'
(lldb) r
... breakpoint hit ...
(lldb) po (id)$x0                 # self
(lldb) expr -l objc++ -O -- (Class)object_getClass((id)$x0)
```
- Dump Objective‑C meta verileri taşıyan bölümleri (note: birçoğu artık `__DATA_CONST` / `__AUTH_CONST` içinde):
```lldb
(lldb) image dump section --section __DATA_CONST.__objc_classlist
(lldb) image dump section --section __DATA_CONST.__objc_selrefs
(lldb) image dump section --section __AUTH_CONST.__auth_got
```
- Bilinen bir sınıf nesnesinin belleğini okuyun ve metod listelerini tersine çevirirken `class_ro_t` / `class_rw_t` üzerinde pivot yapın:
```lldb
(lldb) image lookup -r -n _OBJC_CLASS_$_NSFileManager
(lldb) memory read -fx -s8 0xADDRESS_OF_CLASS_OBJECT
```
### Frida (Objective‑C and Swift)

Frida, semboller olmadan canlı nesneleri keşfetmek ve enstrümante etmek için çok kullanışlı yüksek seviyeli çalışma zamanı köprüleri sağlar:

- Sınıfları ve metotları listeleme, gerçek sınıf adlarını çalışma zamanında çözme ve Objective‑C selectors'ı yakalama:
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
- Swift bridge: Swift türlerini listeleyin ve Swift örnekleriyle etkileşim kurun (güncel Frida gerektirir; Apple Silicon hedeflerinde çok kullanışlı).

---

## References

- Clang/LLVM: Pointer Authentication ve `<ptrauth.h>` intrinsics (arm64e ABI). https://clang.llvm.org/docs/PointerAuthentication.html
- Apple objc runtime headers (tagged pointers, non‑pointer `isa`, etc.) e.g., `objc-object.h`. https://opensource.apple.com/source/objc4/objc4-818.2/runtime/objc-object.h.auto.html

{{#include ../../../banners/hacktricks-training.md}}
