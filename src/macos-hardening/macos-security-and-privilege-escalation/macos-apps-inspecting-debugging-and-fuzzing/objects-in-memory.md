# 메모리의 객체

{{#include ../../../banners/hacktricks-training.md}}

## CFRuntimeClass

CF* 객체는 CoreFoundation에서 유래하며, `CFString`, `CFNumber` 또는 `CFAllocator`와 같은 50개 이상의 클래스 객체를 제공합니다.

이 모든 클래스는 `CFRuntimeClass` 클래스의 인스턴스이며, 호출될 때 `__CFRuntimeClassTable`에 대한 인덱스를 반환합니다. CFRuntimeClass는 [**CFRuntime.h**](https://opensource.apple.com/source/CF/CF-1153.18/CFRuntime.h.auto.html)에서 정의되어 있습니다:
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

Objective‑C 런타임에서 사용하는 대부분의 데이터는 실행 중에 변경되므로, 메모리의 Mach‑O `__DATA` 계열 세그먼트에 있는 여러 섹션을 사용합니다. 역사적으로 이들에는 다음이 포함되었습니다:

- `__objc_msgrefs` (`message_ref_t`): 메시지 참조
- `__objc_ivar` (`ivar`): 인스턴스 변수
- `__objc_data` (`...`): 가변 데이터
- `__objc_classrefs` (`Class`): 클래스 참조
- `__objc_superrefs` (`Class`): 슈퍼클래스 참조
- `__objc_protorefs` (`protocol_t *`): 프로토콜 참조
- `__objc_selrefs` (`SEL`): 셀렉터 참조
- `__objc_const` (`...`): 클래스 읽기 전용 데이터 및 기타 (가능한) 상수 데이터
- `__objc_imageinfo` (`version, flags`): 이미지 로드 중에 사용: 버전은 현재 `0`; 플래그는 사전 최적화된 GC 지원 등 지정
- `__objc_protolist` (`protocol_t *`): 프로토콜 목록
- `__objc_nlcatlist` (`category_t`): 이 바이너리에 정의된 Non-Lazy 카테고리에 대한 포인터
- `__objc_catlist` (`category_t`): 이 바이너리에 정의된 카테고리에 대한 포인터
- `__objc_nlclslist` (`classref_t`): 이 바이너리에 정의된 Non-Lazy Objective‑C 클래스에 대한 포인터
- `__objc_classlist` (`classref_t`): 이 바이너리에 정의된 모든 Objective‑C 클래스에 대한 포인터들

상수를 저장하기 위해 `__TEXT` 세그먼트의 몇몇 섹션도 사용됩니다:

- `__objc_methname` (C‑String): 메서드 이름
- `__objc_classname` (C‑String): 클래스 이름
- `__objc_methtype` (C‑String): 메서드 타입

최신 macOS/iOS(특히 Apple Silicon)에서는 Objective‑C/Swift 메타데이터를 다음에 배치하기도 합니다:

- `__DATA_CONST`: 프로세스 간에 읽기 전용으로 공유할 수 있는 불변 Objective‑C 메타데이터(예: 많은 `__objc_*` 목록이 이제 여기에 존재)
- `__AUTH` / `__AUTH_CONST`: arm64e에서 로드 시 또는 사용 시 인증되어야 하는 포인터를 포함하는 세그먼트(포인터 인증). 또한 레거시 `__la_symbol_ptr`/`__got` 대신 `__AUTH_CONST`에 `__auth_got`을 보게 됩니다. 인스트루먼트나 후킹을 할 때는 최신 바이너리에서 `__got`과 `__auth_got` 엔트리 둘 다를 고려해야 합니다.

dyld 사전 최적화(예: selector uniquing 및 class/protocol 사전 계산)에 대한 배경과 공유 캐시에서 로드될 때 왜 이들 섹션 중 많은 부분이 "이미 고정되어 있는지"에 대해서는 Apple `objc-opt` 소스와 dyld shared cache 노트를 참고하세요. 이는 런타임에 메타데이터를 패치할 수 있는 위치와 방법에 영향을 줍니다.

{{#ref}}
../macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.md
{{#endref}}

### Type Encoding

Objective‑C는 단순 및 복합 타입의 selector와 변수 타입을 인코딩하기 위해 mangling을 사용합니다:

- 프리미티브 타입은 타입의 첫 글자를 사용합니다 — `int`는 `i`, `char`는 `c`, `long`은 `l` 등... unsigned인 경우 대문자를 사용합니다(예: `unsigned long`은 `L`).
- 다른 데이터 타입은 `long long`은 `q`, 비트필드는 `b`, 불리언은 `B`, 클래스는 `#`, `id`는 `@`, `char *`는 `*`, 일반 포인터는 `^`, 정의되지 않은 것은 `?` 등 다른 문자나 기호를 사용합니다.
- 배열, 구조체, 유니온은 각각 `[`, `{`, `(`을 사용합니다.

#### Example Method Declaration
```objectivec
- (NSString *)processString:(id)input withOptions:(char *)options andError:(id)error;
```
셀렉터는 `processString:withOptions:andError:` 입니다

#### 타입 인코딩

- `id` 는 `@` 로 인코딩됩니다
- `char *` 는 `*` 로 인코딩됩니다

메서드의 전체 타입 인코딩은 다음과 같습니다:
```less
@24@0:8@16*20^@24
```
#### 상세 분석

1. 반환 타입 (`NSString *`): `@`로 인코딩, 길이 24  
2. `self` (객체 인스턴스): `@`로 인코딩, 오프셋 0  
3. `_cmd` (셀렉터): `:`로 인코딩, 오프셋 8  
4. 첫 번째 인수 (`char * input`): `*`로 인코딩, 오프셋 16  
5. 두 번째 인수 (`NSDictionary * options`): `@`로 인코딩, 오프셋 20  
6. 세 번째 인수 (`NSError ** error`): `^@`로 인코딩, 오프셋 24

셀렉터 + 인코딩으로 메서드를 재구성할 수 있다.

### 클래스

Objective‑C의 클래스는 속성, 메서드 포인터 등으로 구성된 C struct다. struct `objc_class`는 [**source code**](https://opensource.apple.com/source/objc4/objc4-756.2/runtime/objc-runtime-new.h.auto.html)에서 찾을 수 있다:
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
이 클래스는 클래스에 대한 정보를 표시하기 위해 `isa` 필드의 일부 비트를 사용합니다.

그 다음, 해당 struct는 디스크에 저장된 `class_ro_t` struct를 가리키는 포인터를 가지며, 이 구조체에는 이름, 기본 메서드, 속성, 인스턴스 변수 같은 클래스 속성이 들어 있습니다. 런타임 동안에는 메서드, 프로토콜, 속성처럼 변경될 수 있는 포인터를 포함하는 추가 구조체인 `class_rw_t`가 사용됩니다.

{{#ref}}
../macos-basic-objective-c.md
{{#endref}}

---

## Modern object representations in memory (arm64e, tagged pointers, Swift)

### Non‑pointer `isa` and Pointer Authentication (arm64e)

Apple Silicon과 최신 런타임에서는 Objective‑C `isa`가 항상 원시 class 포인터가 아닙니다. arm64e에서는 PAC(Pointer Authentication Code)를 포함할 수도 있는 패킹된 구조체입니다. 플랫폼에 따라 `nonpointer`, `has_assoc`, `weakly_referenced`, `extra_rc` 등 필드와 (시프트되거나 서명된) 클래스 포인터 자체를 포함할 수 있습니다. 따라서 Objective‑C 객체의 처음 8바이트를 무작정 역참조하면 항상 유효한 `Class` 포인터가 나오지 않을 수 있습니다.

arm64e 디버깅 실무 노트:

- LLDB는 보통 `po`로 Objective‑C 객체를 출력할 때 PAC 비트를 제거해 주지만, raw pointer로 작업할 때는 인증을 수동으로 제거해야 할 수 있습니다:

```lldb
(lldb) expr -l objc++ -- #include <ptrauth.h>
(lldb) expr -l objc++ -- void *raw = ptrauth_strip((void*)0x000000016f123abc, ptrauth_key_asda);
(lldb) expr -l objc++ -O -- (Class)object_getClass((id)raw)
```

- 많은 Mach‑O의 함수/데이터 포인터는 `__AUTH`/`__AUTH_CONST`에 위치하며 사용 전에 인증이 필요합니다. interposing 또는 재바인딩(예: fishhook‑style)을 할 경우, 레거시 `__got`뿐 아니라 `__auth_got`도 처리해야 합니다.

언어/ABI 보장과 Clang/LLVM에서 제공하는 `<ptrauth.h>` 인트린식에 대한 자세한 내용은 이 페이지 끝의 참조를 보세요.

### Tagged pointer objects

일부 Foundation 클래스는 객체의 페이로드를 포인터 값에 직접 인코딩(태그된 포인터)하여 힙 할당을 피합니다. 감지는 플랫폼마다 다르며(예: arm64에서는 최상위 비트, x86_64 macOS에서는 최하위 비트) 태그된 객체는 메모리에 일반적인 `isa`를 저장하지 않으며 런타임이 태그 비트로부터 클래스를 결정합니다. 임의의 `id` 값을 검사할 때:

- `isa` 필드를 직접 건드리지 말고 런타임 API를 사용하세요: `object_getClass(obj)` / `[obj class]`.
- LLDB에서 `po (id)0xADDR`만으로도 런타임에서 클래스를 확인해 태그된 포인터 인스턴스를 올바르게 출력합니다.

### Swift heap objects and metadata

순수 Swift 클래스도 Objective‑C `isa`가 아닌 Swift 메타데이터를 가리키는 헤더를 가진 객체입니다. 수정 없이 실행 중인 Swift 프로세스를 조사하려면 Swift 툴체인의 `swift-inspect`를 사용할 수 있으며, 이는 Remote Mirror 라이브러리를 활용해 런타임 메타데이터를 읽습니다:
```bash
# Xcode toolchain (or Swift.org toolchain) provides swift-inspect
swift-inspect dump-raw-metadata <pid-or-name>
swift-inspect dump-arrays <pid-or-name>
# On Darwin additionally:
swift-inspect dump-concurrency <pid-or-name>
```
이것은 혼합 Swift/ObjC 앱을 리버스 엔지니어링할 때 Swift 힙 객체와 프로토콜 준수를 매핑하는 데 매우 유용합니다.

---

## Runtime inspection cheatsheet (LLDB / Frida)

### LLDB

- 원시 포인터에서 객체 또는 클래스 출력:
```lldb
(lldb) expr -l objc++ -O -- (id)0x0000000101234560
(lldb) expr -l objc++ -O -- (Class)object_getClass((id)0x0000000101234560)
```
- 브레이크포인트에서 객체 메서드의 `self` 포인터로부터 Objective‑C 클래스를 검사하기:
```lldb
(lldb) br se -n '-[NSFileManager fileExistsAtPath:]'
(lldb) r
... breakpoint hit ...
(lldb) po (id)$x0                 # self
(lldb) expr -l objc++ -O -- (Class)object_getClass((id)$x0)
```
- Objective‑C 메타데이터를 포함하는 섹션을 덤프합니다 (참고: 많은 섹션이 이제 `__DATA_CONST` / `__AUTH_CONST`에 있습니다):
```lldb
(lldb) image dump section --section __DATA_CONST.__objc_classlist
(lldb) image dump section --section __DATA_CONST.__objc_selrefs
(lldb) image dump section --section __AUTH_CONST.__auth_got
```
- 알려진 클래스 객체의 메모리를 읽어 `class_ro_t` / `class_rw_t` 로 pivot하여 메서드 목록을 역분석할 때:
```lldb
(lldb) image lookup -r -n _OBJC_CLASS_$_NSFileManager
(lldb) memory read -fx -s8 0xADDRESS_OF_CLASS_OBJECT
```
### Frida (Objective‑C and Swift)

Frida는 심볼 없이도 라이브 객체를 탐색하고 계측할 수 있게 해주는 고수준 런타임 브리지를 제공합니다:

- 클래스와 메서드를 열거하고, 런타임에 실제 클래스 이름을 확인하며, Objective‑C selectors를 가로챌 수 있습니다:
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
- Swift bridge: Swift 타입을 열거하고 Swift 인스턴스와 상호작용합니다 (최신 Frida 필요; Apple Silicon 타깃에서 매우 유용).

---

## 참고 자료

- Clang/LLVM: Pointer Authentication 및 `<ptrauth.h>` intrinsics (arm64e ABI). https://clang.llvm.org/docs/PointerAuthentication.html
- Apple objc runtime headers (tagged pointers, non‑pointer `isa`, etc.) 예: `objc-object.h`. https://opensource.apple.com/source/objc4/objc4-818.2/runtime/objc-object.h.auto.html

{{#include ../../../banners/hacktricks-training.md}}
