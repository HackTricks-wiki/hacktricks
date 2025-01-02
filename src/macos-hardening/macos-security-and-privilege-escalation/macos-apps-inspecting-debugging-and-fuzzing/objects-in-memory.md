# 메모리의 객체

{{#include ../../../banners/hacktricks-training.md}}

## CFRuntimeClass

CF\* 객체는 CoreFoundation에서 제공되며, `CFString`, `CFNumber` 또는 `CFAllocator`와 같은 50개 이상의 객체 클래스를 제공합니다.

이 모든 클래스는 `CFRuntimeClass` 클래스의 인스턴스이며, 호출 시 `__CFRuntimeClassTable`에 대한 인덱스를 반환합니다. CFRuntimeClass는 [**CFRuntime.h**](https://opensource.apple.com/source/CF/CF-1153.18/CFRuntime.h.auto.html)에서 정의됩니다:
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

### 메모리 섹션 사용

ObjectiveC 런타임에서 사용하는 대부분의 데이터는 실행 중에 변경되므로, 메모리의 **\_\_DATA** 세그먼트에서 일부 섹션을 사용합니다:

- **`__objc_msgrefs`** (`message_ref_t`): 메시지 참조
- **`__objc_ivar`** (`ivar`): 인스턴스 변수
- **`__objc_data`** (`...`): 변경 가능한 데이터
- **`__objc_classrefs`** (`Class`): 클래스 참조
- **`__objc_superrefs`** (`Class`): 슈퍼클래스 참조
- **`__objc_protorefs`** (`protocol_t *`): 프로토콜 참조
- **`__objc_selrefs`** (`SEL`): 선택자 참조
- **`__objc_const`** (`...`): 클래스 `r/o` 데이터 및 기타 (희망적으로) 상수 데이터
- **`__objc_imageinfo`** (`version, flags`): 이미지 로드 중 사용: 현재 버전 `0`; 플래그는 사전 최적화된 GC 지원 등을 지정합니다.
- **`__objc_protolist`** (`protocol_t *`): 프로토콜 목록
- **`__objc_nlcatlist`** (`category_t`): 이 바이너리에서 정의된 비지연 카테고리에 대한 포인터
- **`__objc_catlist`** (`category_t`): 이 바이너리에서 정의된 카테고리에 대한 포인터
- **`__objc_nlclslist`** (`classref_t`): 이 바이너리에서 정의된 비지연 Objective-C 클래스에 대한 포인터
- **`__objc_classlist`** (`classref_t`): 이 바이너리에서 정의된 모든 Objective-C 클래스에 대한 포인터

또한, 이 섹션에 쓸 수 없는 상수 값을 저장하기 위해 **`__TEXT`** 세그먼트의 몇 가지 섹션을 사용합니다:

- **`__objc_methname`** (C-String): 메서드 이름
- **`__objc_classname`** (C-String): 클래스 이름
- **`__objc_methtype`** (C-String): 메서드 유형

### 타입 인코딩

Objective-C는 선택자 및 변수 유형을 단순 및 복합 유형으로 인코딩하기 위해 일부 맹글링을 사용합니다:

- 원시 유형은 유형의 첫 글자를 사용합니다. `i`는 `int`, `c`는 `char`, `l`은 `long`...이며, 부호 없는 경우 대문자를 사용합니다 (`L`은 `unsigned Long`).
- 다른 데이터 유형의 글자가 사용되거나 특별한 경우, `q`는 `long long`, `b`는 `bitfields`, `B`는 `booleans`, `#`는 `classes`, `@`는 `id`, `*`는 `char pointers`, `^`는 일반 `pointers`, `?`는 `undefined`와 같은 다른 글자나 기호를 사용합니다.
- 배열, 구조체 및 유니온은 `[`, `{` 및 `(`를 사용합니다.

#### 예제 메서드 선언
```objectivec
- (NSString *)processString:(id)input withOptions:(char *)options andError:(id)error;
```
선택자는 `processString:withOptions:andError:`입니다.

#### 타입 인코딩

- `id`는 `@`로 인코딩됩니다.
- `char *`는 `*`로 인코딩됩니다.

메서드의 전체 타입 인코딩은:
```less
@24@0:8@16*20^@24
```
#### 상세 분석

1. **반환 유형 (`NSString *`)**: 길이 24로 `@`로 인코딩됨
2. **`self` (객체 인스턴스)**: 오프셋 0에서 `@`로 인코딩됨
3. **`_cmd` (선택자)**: 오프셋 8에서 `:`로 인코딩됨
4. **첫 번째 인수 (`char * input`)**: 오프셋 16에서 `*`로 인코딩됨
5. **두 번째 인수 (`NSDictionary * options`)**: 오프셋 20에서 `@`로 인코딩됨
6. **세 번째 인수 (`NSError ** error`)**: 오프셋 24에서 `^@`로 인코딩됨

**선택자와 인코딩을 통해 메서드를 재구성할 수 있습니다.**

### **클래스**

Objective-C의 클래스는 속성, 메서드 포인터가 있는 구조체입니다... 구조체 `objc_class`를 찾는 것이 가능합니다 [**소스 코드**](https://opensource.apple.com/source/objc4/objc4-756.2/runtime/objc-runtime-new.h.auto.html):
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
이 클래스는 isa 필드의 일부 비트를 사용하여 클래스에 대한 정보를 나타냅니다.

그런 다음, 이 구조체는 클래스의 이름, 기본 메서드, 속성 및 인스턴스 변수를 포함하는 디스크에 저장된 `class_ro_t` 구조체에 대한 포인터를 가지고 있습니다.\
런타임 동안에는 메서드, 프로토콜, 속성 등을 변경할 수 있는 포인터를 포함하는 추가 구조체 `class_rw_t`가 사용됩니다.

{{#include ../../../banners/hacktricks-training.md}}
