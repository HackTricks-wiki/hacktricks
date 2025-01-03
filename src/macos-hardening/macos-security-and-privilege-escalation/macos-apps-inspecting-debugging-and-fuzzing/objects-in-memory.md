# 内存中的对象

{{#include ../../../banners/hacktricks-training.md}}

## CFRuntimeClass

CF\* 对象来自 CoreFoundation，它提供了超过 50 种对象类，如 `CFString`、`CFNumber` 或 `CFAllocator`。

所有这些类都是 `CFRuntimeClass` 类的实例，当调用时，它返回一个指向 `__CFRuntimeClassTable` 的索引。CFRuntimeClass 在 [**CFRuntime.h**](https://opensource.apple.com/source/CF/CF-1153.18/CFRuntime.h.auto.html) 中定义：
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

### 内存使用的部分

大多数由 ObjectiveC 运行时使用的数据在执行期间会发生变化，因此它使用内存中的一些 **\_\_DATA** 段：

- **`__objc_msgrefs`** (`message_ref_t`): 消息引用
- **`__objc_ivar`** (`ivar`): 实例变量
- **`__objc_data`** (`...`): 可变数据
- **`__objc_classrefs`** (`Class`): 类引用
- **`__objc_superrefs`** (`Class`): 超类引用
- **`__objc_protorefs`** (`protocol_t *`): 协议引用
- **`__objc_selrefs`** (`SEL`): 选择器引用
- **`__objc_const`** (`...`): 类 `r/o` 数据和其他（希望是）常量数据
- **`__objc_imageinfo`** (`version, flags`): 在图像加载期间使用：当前版本 `0`；标志指定预优化的 GC 支持等。
- **`__objc_protolist`** (`protocol_t *`): 协议列表
- **`__objc_nlcatlist`** (`category_t`): 指向此二进制文件中定义的非延迟类别的指针
- **`__objc_catlist`** (`category_t`): 指向此二进制文件中定义的类别的指针
- **`__objc_nlclslist`** (`classref_t`): 指向此二进制文件中定义的非延迟 Objective-C 类的指针
- **`__objc_classlist`** (`classref_t`): 指向此二进制文件中定义的所有 Objective-C 类的指针

它还使用 **`__TEXT`** 段中的一些部分来存储常量值，如果无法在此部分写入：

- **`__objc_methname`** (C-String): 方法名称
- **`__objc_classname`** (C-String): 类名称
- **`__objc_methtype`** (C-String): 方法类型

### 类型编码

Objective-C 使用一些混淆来编码简单和复杂类型的选择器和变量类型：

- 原始类型使用其类型的首字母 `i` 表示 `int`，`c` 表示 `char`，`l` 表示 `long`... 并在无符号的情况下使用大写字母（`L` 表示 `unsigned Long`）。
- 其他字母被使用或是特殊的数据类型，使用其他字母或符号，如 `q` 表示 `long long`，`b` 表示 `bitfields`，`B` 表示 `booleans`，`#` 表示 `classes`，`@` 表示 `id`，`*` 表示 `char pointers`，`^` 表示通用 `pointers` 和 `?` 表示 `undefined`。
- 数组、结构和联合使用 `[`, `{` 和 `(`

#### 示例方法声明
```objectivec
- (NSString *)processString:(id)input withOptions:(char *)options andError:(id)error;
```
选择器将是 `processString:withOptions:andError:`

#### 类型编码

- `id` 编码为 `@`
- `char *` 编码为 `*`

该方法的完整类型编码为：
```less
@24@0:8@16*20^@24
```
#### 详细分解

1. **返回类型 (`NSString *`)**: 编码为 `@`，长度为 24
2. **`self` (对象实例)**: 编码为 `@`，偏移量为 0
3. **`_cmd` (选择器)**: 编码为 `:`，偏移量为 8
4. **第一个参数 (`char * input`)**: 编码为 `*`，偏移量为 16
5. **第二个参数 (`NSDictionary * options`)**: 编码为 `@`，偏移量为 20
6. **第三个参数 (`NSError ** error`)**: 编码为 `^@`，偏移量为 24

**通过选择器和编码，你可以重建该方法。**

### **类**

Objective-C 中的类是一个具有属性、方法指针的结构体... 可以在 [**源代码**](https://opensource.apple.com/source/objc4/objc4-756.2/runtime/objc-runtime-new.h.auto.html) 中找到结构体 `objc_class`：
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
这个类使用 isa 字段的一些位来指示有关该类的信息。

然后，结构体有一个指向存储在磁盘上的 `class_ro_t` 结构体的指针，该结构体包含类的属性，如其名称、基本方法、属性和实例变量。\
在运行时，使用一个额外的结构体 `class_rw_t`，其中包含可以被更改的指针，例如方法、协议、属性... 

{{#include ../../../banners/hacktricks-training.md}}
