# memory में Objects

{{#include ../../../banners/hacktricks-training.md}}

## CFRuntimeClass

CF* objects, CoreFoundation से आते हैं, जो `CFString`, `CFNumber` या `CFAllocator` जैसे 50 से अधिक classes of objects प्रदान करता है।

ये सभी classes, `CFRuntimeClass` class के instances हैं। इसे call करने पर यह `__CFRuntimeClassTable` का एक index लौटाता है। CFRuntimeClass को [**CFRuntime.h**](https://opensource.apple.com/source/CF/CF-1153.18/CFRuntime.h.auto.html) में define किया गया है:
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

### उपयोग किए गए Memory sections

Objective-C runtime द्वारा उपयोग किए जाने वाला अधिकांश data execution के दौरान बदलता रहेगा, इसलिए यह memory में Mach-O `__DATA` family of segments के कई sections का उपयोग करता है। ऐतिहासिक रूप से इनमें शामिल थे:

- `__objc_msgrefs` (`message_ref_t`): Message references
- `__objc_ivar` (`ivar`): Instance variables
- `__objc_data` (`...`): Mutable data
- `__objc_classrefs` (`Class`): Class references
- `__objc_superrefs` (`Class`): Superclass references
- `__objc_protorefs` (`protocol_t *`): Protocol references
- `__objc_selrefs` (`SEL`): Selector references
- `__objc_const` (`...`): Class r/o data और अन्य (आशा है कि) constant data
- `__objc_imageinfo` (`version, flags`): Image load के दौरान उपयोग किया जाता है: वर्तमान Version `0` है; Flags preoptimized GC support आदि निर्दिष्ट करते हैं।
- `__objc_protolist` (`protocol_t *`): Protocol list
- `__objc_nlcatlist` (`category_t`): इस binary में defined Non-Lazy Categories का Pointer
- `__objc_catlist` (`category_t`): इस binary में defined Categories का Pointer
- `__objc_nlclslist` (`classref_t`): इस binary में defined Non-Lazy Objective-C classes का Pointer
- `__objc_classlist` (`classref_t`): इस binary में defined सभी Objective-C classes के Pointers

Constants को store करने के लिए यह `__TEXT` segment में कुछ sections का भी उपयोग करता है:

- `__objc_methname` (C‑String): Method names
- `__objc_classname` (C‑String): Class names
- `__objc_methtype` (C‑String): Method types

Modern macOS/iOS (विशेषकर Apple Silicon पर) Objective-C/Swift metadata को निम्न में भी रखते हैं:

- `__DATA_CONST`: immutable Objective-C metadata जिसे processes के बीच read-only रूप में share किया जा सकता है (उदाहरण के लिए, कई `__objc_*` lists अब यहां रहती हैं)।
- `__AUTH` / `__AUTH_CONST`: ऐसे Pointers वाले segments जिन्हें arm64e (Pointer Authentication) पर load या use-time पर authenticated किया जाना आवश्यक है। Legacy `__la_symbol_ptr`/`__got` के बजाय `__AUTH_CONST` में आपको `__auth_got` भी दिखाई देगा। Instrumenting या hooking करते समय modern binaries में `__got` और `__auth_got` दोनों entries को ध्यान में रखें।

dyld pre-optimization (जैसे selector uniquing और class/protocol precomputation) की background जानकारी और यह समझने के लिए कि shared cache से आने पर इनमें से कई sections "already fixed up" क्यों होते हैं, Apple के `objc-opt` sources और dyld shared cache notes देखें। इससे प्रभावित होता है कि runtime पर metadata को कहां और कैसे patch किया जा सकता है।

{{#ref}}
../macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.md
{{#endref}}

### Type Encoding

Objective-C simple और complex types के selectors तथा variable types को encode करने के लिए mangling का उपयोग करता है:

- Primitive types अपने type के पहले letter का उपयोग करते हैं: `int` के लिए `i`, `char` के लिए `c`, `long` के लिए `l`... और unsigned होने पर capital letter का उपयोग करते हैं (`unsigned long` के लिए `L`)।
- अन्य data types दूसरे letters या symbols का उपयोग करते हैं, जैसे `long long` के लिए `q`, bitfields के लिए `b`, booleans के लिए `B`, classes के लिए `#`, `id` के लिए `@`, `char *` के लिए `*`, generic pointers के लिए `^` और undefined के लिए `?`।
- Arrays, structures और unions क्रमशः `[`, `{` और `(` का उपयोग करते हैं।

#### Example Method Declaration
```objectivec
- (NSString *)processString:(id)input withOptions:(char *)options andError:(id)error;
```
The selector `processString:withOptions:andError:` होगा।

#### Type Encoding

- `id` को `@` के रूप में encoded किया जाता है
- `char *` को `*` के रूप में encoded किया जाता है

इस method का complete type encoding है:
```less
@24@0:8@16*20^@24
```
#### विस्तृत विवरण

1. Return Type (`NSString *`): लंबाई 24 के साथ `@` के रूप में encoded
2. `self` (object instance): `@` के रूप में encoded, offset 0 पर
3. `_cmd` (selector): `:` के रूप में encoded, offset 8 पर
4. पहला argument (`char * input`): `*` के रूप में encoded, offset 16 पर
5. दूसरा argument (`NSDictionary * options`): `@` के रूप में encoded, offset 20 पर
6. तीसरा argument (`NSError ** error`): `^@` के रूप में encoded, offset 24 पर

selector और encoding की सहायता से आप method को reconstruct कर सकते हैं।

### Classes

Objective-C में Classes properties, method pointers आदि वाले C structs होते हैं। `objc_class` struct को [**source code**](https://opensource.apple.com/source/objc4/objc4-756.2/runtime/objc-runtime-new.h.auto.html) में ढूँढना संभव है:
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
यह class `isa` field के कुछ bits का उपयोग class के बारे में information बताने के लिए करती है।

फिर, struct में disk पर stored struct `class_ro_t` का एक pointer होता है, जिसमें class के attributes जैसे उसका name, base methods, properties और instance variables होते हैं। Runtime के दौरान एक additional structure `class_rw_t` का उपयोग किया जाता है, जिसमें ऐसे pointers होते हैं जिन्हें बदला जा सकता है, जैसे methods, protocols और properties।

{{#ref}}
../macos-basic-objective-c.md
{{#endref}}

---

## Memory में modern object representations (arm64e, tagged pointers, Swift)

### Non-pointer `isa` और Pointer Authentication (arm64e)

Apple Silicon और recent runtimes पर Objective-C `isa` हमेशा raw class pointer नहीं होता। arm64e पर यह एक packed structure होता है, जिसमें Pointer Authentication Code (PAC) भी हो सकता है। Platform के आधार पर इसमें `nonpointer`, `has_assoc`, `weakly_referenced`, `extra_rc` और class pointer स्वयं जैसे fields शामिल हो सकते हैं (shifted या signed रूप में)। इसका अर्थ है कि Objective-C object के पहले 8 bytes को blindly dereference करने पर हमेशा valid `Class` pointer प्राप्त नहीं होगा।<sup>[2]</sup>

arm64e पर debugging करते समय practical notes:

- Objective-C objects को `po` से print करते समय LLDB आमतौर पर PAC bits को आपके लिए strip कर देता है, लेकिन raw pointers के साथ काम करते समय authentication को manually strip करना पड़ सकता है:

```lldb
(lldb) expr -l objc++ -- #include <ptrauth.h>
(lldb) expr -l objc++ -- void *raw = ptrauth_strip((void*)0x000000016f123abc, ptrauth_key_asda);
(lldb) expr -l objc++ -O -- (Class)object_getClass((id)raw)
```

- Mach-O में कई function/data pointers `__AUTH`/`__AUTH_CONST` में स्थित होंगे और उपयोग से पहले authentication आवश्यक होगा। यदि आप interposing या re-binding कर रहे हैं (जैसे fishhook-style), तो सुनिश्चित करें कि आप legacy `__got` के अतिरिक्त `__auth_got` को भी handle करें।

Language/ABI guarantees और Clang/LLVM से उपलब्ध `<ptrauth.h>` intrinsics की deep dive के लिए इस page के अंत में दिए गए reference को देखें।<sup>[1]</sup>

### Tagged pointer objects

कुछ Foundation classes object के payload को सीधे pointer value में encode करके heap allocation से बचती हैं (tagged pointers)। Detection platform के अनुसार अलग होती है (उदाहरण के लिए, arm64 पर most-significant bit और x86_64 macOS पर least-significant bit)। Tagged objects में memory में regular `isa` stored नहीं होता; runtime tag bits से class resolve करता है।<sup>[2]</sup> Arbitrary `id` values का inspection करते समय:

- `isa` field को poke करने के बजाय runtime APIs का उपयोग करें: `object_getClass(obj)` / `[obj class]`।
- LLDB में केवल `po (id)0xADDR` tagged pointer instances को सही तरीके से print करेगा, क्योंकि class resolve करने के लिए runtime से consult किया जाता है।

### Swift heap objects और metadata

Pure Swift classes भी objects होती हैं, जिनके header में Objective-C `isa` के बजाय Swift metadata का pointer होता है। Live Swift processes को modify किए बिना introspect करने के लिए आप Swift toolchain के `swift-inspect` का उपयोग कर सकते हैं, जो runtime metadata पढ़ने के लिए Remote Mirror library का उपयोग करता है:
```bash
# Xcode toolchain (or Swift.org toolchain) provides swift-inspect
swift-inspect dump-raw-metadata <pid-or-name>
swift-inspect dump-arrays <pid-or-name>
# On Darwin additionally:
swift-inspect dump-concurrency <pid-or-name>
```
Swift/ObjC मिश्रित apps को reverse करते समय Swift heap objects और protocol conformances को map करने के लिए यह बहुत उपयोगी है।

---

## Runtime inspection cheatsheet (LLDB / Frida)

### LLDB

- raw pointer से object या class print करें:
```lldb
(lldb) expr -l objc++ -O -- (id)0x0000000101234560
(lldb) expr -l objc++ -O -- (Class)object_getClass((id)0x0000000101234560)
```
- breakpoint में object method के `self` के pointer से Objective-C class का निरीक्षण करें:
```lldb
(lldb) br se -n '-[NSFileManager fileExistsAtPath:]'
(lldb) r
... breakpoint hit ...
(lldb) po (id)$x0                 # self
(lldb) expr -l objc++ -O -- (Class)object_getClass((id)$x0)
```
- Objective-C metadata रखने वाले sections को dump करें (ध्यान दें: कई अब `__DATA_CONST` / `__AUTH_CONST` में हैं):
```lldb
(lldb) image dump section --section __DATA_CONST.__objc_classlist
(lldb) image dump section --section __DATA_CONST.__objc_selrefs
(lldb) image dump section --section __AUTH_CONST.__auth_got
```
- method lists को reverse करते समय `class_ro_t` / `class_rw_t` पर pivot करने के लिए किसी ज्ञात class object की memory पढ़ें:
```lldb
(lldb) image lookup -r -n _OBJC_CLASS_$_NSFileManager
(lldb) memory read -fx -s8 0xADDRESS_OF_CLASS_OBJECT
```
### Frida (Objective‑C और Swift)

Frida high-level runtime bridges प्रदान करता है, जो symbols के बिना live objects को खोजने और instrument करने के लिए बहुत उपयोगी हैं:

- classes और methods को enumerate करें, runtime पर actual class names को resolve करें, और Objective‑C selectors को intercept करें:
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
- Swift bridge: Swift types enumerate करें और Swift instances के साथ interact करें (इसके लिए recent Frida आवश्यक है; Apple Silicon targets पर बहुत उपयोगी)।

---

## References

- [1] [Clang/LLVM: Pointer Authentication and the ptrauth.h intrinsics (arm64e ABI)](https://clang.llvm.org/docs/PointerAuthentication.html)
- [2] [Apple objc runtime headers - objc-object.h (tagged pointers, non‑pointer isa, etc.)](https://opensource.apple.com/source/objc4/objc4-818.2/runtime/objc-object.h.auto.html)

{{#include ../../../banners/hacktricks-training.md}}
