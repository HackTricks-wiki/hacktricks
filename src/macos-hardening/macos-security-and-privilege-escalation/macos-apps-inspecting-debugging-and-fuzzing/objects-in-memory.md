# 메모리 내 객체

{{#include ../../../banners/hacktricks-training.md}}

## CFRuntimeClass

CF* 객체는 `CFString`, `CFNumber`, `CFAllocator`와 같은 50개 이상의 객체 클래스를 제공하는 CoreFoundation에서 비롯됩니다.

이러한 모든 클래스는 `CFRuntimeClass` 클래스의 인스턴스이며, 이를 호출하면 `__CFRuntimeClassTable`의 인덱스가 반환됩니다. CFRuntimeClass는 [**CFRuntime.h**](https://opensource.apple.com/source/CF/CF-1153.18/CFRuntime.h.auto.html)에 정의되어 있습니다.
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

### 사용되는 메모리 섹션

Objective-C runtime에서 사용하는 대부분의 데이터는 실행 중 변경되므로, 메모리의 Mach-O `__DATA` 계열 세그먼트에 있는 여러 섹션을 사용합니다. 역사적으로 다음 섹션이 포함되었습니다.

- `__objc_msgrefs` (`message_ref_t`): Message references
- `__objc_ivar` (`ivar`): Instance variables
- `__objc_data` (`...`): Mutable data
- `__objc_classrefs` (`Class`): Class references
- `__objc_superrefs` (`Class`): Superclass references
- `__objc_protorefs` (`protocol_t *`): Protocol references
- `__objc_selrefs` (`SEL`): Selector references
- `__objc_const` (`...`): Class r/o data 및 기타 (희망적으로) constant data
- `__objc_imageinfo` (`version, flags`): image load 중 사용됨: 현재 `Version`은 `0`; `Flags`는 preoptimized GC support 등을 지정함
- `__objc_protolist` (`protocol_t *`): Protocol list
- `__objc_nlcatlist` (`category_t`): 이 binary에 정의된 Non-Lazy Categories를 가리키는 Pointer
- `__objc_catlist` (`category_t`): 이 binary에 정의된 Categories를 가리키는 Pointer
- `__objc_nlclslist` (`classref_t`): 이 binary에 정의된 Non-Lazy Objective-C classes를 가리키는 Pointer
- `__objc_classlist` (`classref_t`): 이 binary에 정의된 모든 Objective-C classes를 가리키는 Pointers

또한 constants를 저장하기 위해 `__TEXT` 세그먼트의 일부 섹션도 사용합니다.

- `__objc_methname` (C-String): Method names
- `__objc_classname` (C-String): Class names
- `__objc_methtype` (C-String): Method types

Modern macOS/iOS(특히 Apple Silicon)에서는 Objective-C/Swift metadata를 다음 위치에도 저장합니다.

- `__DATA_CONST`: 프로세스 간 read-only로 공유할 수 있는 immutable Objective-C metadata(예: 현재 많은 `__objc_*` lists가 여기에 존재함)
- `__AUTH` / `__AUTH_CONST`: arm64e(Pointer Authentication)에서 load 또는 use-time에 인증해야 하는 pointers를 포함하는 세그먼트입니다. 또한 legacy `__la_symbol_ptr`/`__got` 대신 `__AUTH_CONST`에 있는 `__auth_got`도 확인할 수 있습니다. Modern binaries를 instrumenting하거나 hooking할 때는 `__got` 및 `__auth_got` entries를 모두 고려해야 합니다.

dyld pre-optimization(예: selector uniquing 및 class/protocol precomputation)의 배경과 shared cache에서 가져온 경우 이러한 섹션 중 상당수가 왜 "already fixed up" 상태인지 알아보려면 Apple의 `objc-opt` sources 및 dyld shared cache notes를 확인하세요. 이는 runtime에 metadata를 patch할 수 있는 위치와 방법에 영향을 줍니다.

{{#ref}}
../macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.md
{{#endref}}

### Type Encoding

Objective-C는 단순한 type과 복잡한 type의 selector 및 variable types를 encode하기 위해 mangling을 사용합니다.

- Primitive types는 type의 첫 글자를 사용합니다. `int`에는 `i`, `char`에는 `c`, `long`에는 `l`을 사용하며, unsigned인 경우에는 대문자를 사용합니다(`unsigned long`에는 `L`).
- 그 외의 data types는 `long long`의 `q`, bitfields의 `b`, booleans의 `B`, classes의 `#`, `id`의 `@`, `char *`의 `*`, generic pointers의 `^`, undefined의 `?`와 같은 다른 letters 또는 symbols를 사용합니다.
- Arrays, structures 및 unions에는 각각 `[`, `{`, `(`를 사용합니다.

#### Example Method Declaration
```objectivec
- (NSString *)processString:(id)input withOptions:(char *)options andError:(id)error;
```
The selector는 `processString:withOptions:andError:`입니다.

#### Type Encoding

- `id`는 `@`로 encode됩니다.
- `char *`는 `*`로 encode됩니다.

이 method의 전체 type encoding은 다음과 같습니다.
```less
@24@0:8@16*20^@24
```
#### 상세 분석

1. 반환 타입 (`NSString *`): 길이 24인 `@`로 인코딩됨
2. `self` (객체 인스턴스): `@`로 인코딩되며 오프셋 0
3. `_cmd` (selector): `:`로 인코딩되며 오프셋 8
4. 첫 번째 인자 (`char * input`): `*`로 인코딩되며 오프셋 16
5. 두 번째 인자 (`NSDictionary * options`): `@`로 인코딩되며 오프셋 20
6. 세 번째 인자 (`NSError ** error`): `^@`로 인코딩되며 오프셋 24

selector와 encoding을 사용하면 method를 재구성할 수 있습니다.

### Classes

Objective-C의 Classes는 속성, method pointer 등을 포함하는 C struct입니다. [**소스 코드**](https://opensource.apple.com/source/objc4/objc4-756.2/runtime/objc-runtime-new.h.auto.html)에서 `objc_class` struct를 찾을 수 있습니다:
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
이 class는 `isa` field의 일부 비트를 사용하여 class에 대한 정보를 나타냅니다.

그런 다음 struct에는 디스크에 저장된 `class_ro_t` struct에 대한 pointer가 있으며, 이 struct에는 class의 name, base methods, properties 및 instance variables와 같은 attributes가 포함됩니다. 런타임 중에는 변경 가능한 methods, protocols, properties에 대한 pointers를 포함하는 추가 structure인 `class_rw_t`가 사용됩니다.

{{#ref}}
../macos-basic-objective-c.md
{{#endref}}

---

## 메모리 내 Modern object representations (arm64e, tagged pointers, Swift)

### Non‑pointer `isa` 및 Pointer Authentication (arm64e)

Apple Silicon 및 최신 runtimes에서 Objective‑C `isa`는 항상 raw class pointer인 것은 아닙니다. arm64e에서는 Pointer Authentication Code (PAC)를 함께 저장할 수도 있는 packed structure입니다. Platform에 따라 `nonpointer`, `has_assoc`, `weakly_referenced`, `extra_rc` 및 class pointer 자체(shifted 또는 signed)와 같은 fields가 포함될 수 있습니다. 따라서 Objective‑C object의 처음 8 bytes를 무조건 dereference한다고 해서 항상 유효한 `Class` pointer를 얻을 수 있는 것은 아닙니다.<sup>[2]</sup>

arm64e에서 debugging할 때의 실용적인 참고 사항:

- LLDB는 일반적으로 `po`를 사용하여 Objective‑C objects를 출력할 때 PAC bits를 자동으로 제거하지만, raw pointers를 다룰 때는 authentication을 수동으로 제거해야 할 수 있습니다:

```lldb
(lldb) expr -l objc++ -- #include <ptrauth.h>
(lldb) expr -l objc++ -- void *raw = ptrauth_strip((void*)0x000000016f123abc, ptrauth_key_asda);
(lldb) expr -l objc++ -O -- (Class)object_getClass((id)raw)
```

- Mach‑O의 많은 function/data pointers는 `__AUTH`/`__AUTH_CONST`에 있으며 사용하기 전에 authentication이 필요합니다. interposing 또는 re-binding(예: fishhook-style)을 수행하는 경우 legacy `__got`뿐만 아니라 `__auth_got`도 처리해야 합니다.

Clang/LLVM에서 제공되는 language/ABI guarantees 및 `<ptrauth.h>` intrinsics에 대한 자세한 내용은 이 페이지 끝의 reference를 참조하세요.<sup>[1]</sup>

### Tagged pointer objects

일부 Foundation classes는 object의 payload를 pointer value에 직접 encoding하여 heap allocation을 피합니다(tagged pointers). Detection 방식은 platform에 따라 다릅니다(예: arm64에서는 most-significant bit, x86_64 macOS에서는 least-significant bit). Tagged objects는 memory에 일반적인 `isa`를 저장하지 않습니다. 대신 runtime이 tag bits를 사용하여 class를 resolve합니다.<sup>[2]</sup> 임의의 `id` values를 inspect할 때:

- `isa` field를 직접 확인하지 말고 runtime APIs를 사용하세요: `object_getClass(obj)` / `[obj class]`.
- LLDB에서는 runtime이 class를 resolve하는 데 사용되므로 `po (id)0xADDR`만으로도 tagged pointer instances가 올바르게 출력됩니다.

### Swift heap objects 및 metadata

Pure Swift classes도 Swift metadata를 가리키는 header를 가진 objects이지만, Objective‑C `isa`는 아닙니다. objects를 수정하지 않고 live Swift processes를 introspect하려면 Swift toolchain의 `swift-inspect`를 사용할 수 있습니다. 이 도구는 Remote Mirror library를 활용하여 runtime metadata를 읽습니다:
```bash
# Xcode toolchain (or Swift.org toolchain) provides swift-inspect
swift-inspect dump-raw-metadata <pid-or-name>
swift-inspect dump-arrays <pid-or-name>
# On Darwin additionally:
swift-inspect dump-concurrency <pid-or-name>
```
Swift heap objects와 protocol conformances를 매핑할 때 매우 유용하며, mixed Swift/ObjC apps를 reversing하는 데 사용할 수 있습니다.

---

## Runtime inspection 치트시트 (LLDB / Frida)

### LLDB

- raw pointer에서 object 또는 class 출력:
```lldb
(lldb) expr -l objc++ -O -- (id)0x0000000101234560
(lldb) expr -l objc++ -O -- (Class)object_getClass((id)0x0000000101234560)
```
- breakpoint에서 object method의 `self`에 대한 pointer로 Objective-C class 검사:
```lldb
(lldb) br se -n '-[NSFileManager fileExistsAtPath:]'
(lldb) r
... breakpoint hit ...
(lldb) po (id)$x0                 # self
(lldb) expr -l objc++ -O -- (Class)object_getClass((id)$x0)
```
- Objective-C metadata를 포함하는 섹션을 dump합니다(참고: 현재는 많은 섹션이 `__DATA_CONST` / `__AUTH_CONST`에 있습니다):
```lldb
(lldb) image dump section --section __DATA_CONST.__objc_classlist
(lldb) image dump section --section __DATA_CONST.__objc_selrefs
(lldb) image dump section --section __AUTH_CONST.__auth_got
```
- method list를 reverse engineering할 때 알려진 class object의 memory를 읽어 `class_ro_t` / `class_rw_t`로 pivot합니다:
```lldb
(lldb) image lookup -r -n _OBJC_CLASS_$_NSFileManager
(lldb) memory read -fx -s8 0xADDRESS_OF_CLASS_OBJECT
```
### Frida (Objective‑C 및 Swift)

Frida는 symbols 없이도 실행 중인 objects를 확인하고 instrument하는 데 매우 유용한 high-level runtime bridges를 제공합니다.

- classes와 methods를 열거하고, runtime에서 실제 class 이름을 확인하며, Objective‑C selectors를 intercept합니다:
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
- Swift bridge: Swift type을 열거하고 Swift instance와 상호작용합니다(최신 Frida 필요; Apple Silicon target에서 매우 유용).

---

## References

- [1] [Clang/LLVM: Pointer Authentication 및 ptrauth.h intrinsics (arm64e ABI)](https://clang.llvm.org/docs/PointerAuthentication.html)
- [2] [Apple objc runtime headers - objc-object.h (tagged pointers, non-pointer isa 등)](https://opensource.apple.com/source/objc4/objc4-818.2/runtime/objc-object.h.auto.html)

{{#include ../../../banners/hacktricks-training.md}}
