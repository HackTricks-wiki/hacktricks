# 内存中的对象

{{#include ../../../banners/hacktricks-training.md}}

## CFRuntimeClass

CF* 对象来自 CoreFoundation，CoreFoundation 提供了超过 50 种对象类，例如 `CFString`、`CFNumber` 或 `CFAllocator`。

所有这些类都是 `CFRuntimeClass` 类的实例。调用该类时，会返回 `__CFRuntimeClassTable` 中的一个索引。CFRuntimeClass 的定义位于 [**CFRuntime.h**](https://opensource.apple.com/source/CF/CF-1153.18/CFRuntime.h.auto.html)：
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

### 使用的内存节

Objective-C runtime 使用的大多数数据都会在执行期间发生变化，因此它会使用 Mach-O `__DATA` 系列 segment 在内存中的多个 sections。历史上，这些 sections 包括：

- `__objc_msgrefs` (`message_ref_t`)：Message references
- `__objc_ivar` (`ivar`)：Instance variables
- `__objc_data` (`...`)：Mutable data
- `__objc_classrefs` (`Class`)：Class references
- `__objc_superrefs` (`Class`)：Superclass references
- `__objc_protorefs` (`protocol_t *`)：Protocol references
- `__objc_selrefs` (`SEL`)：Selector references
- `__objc_const` (`...`)：Class r/o data 及其他（希望是）constant data
- `__objc_imageinfo` (`version, flags`)：在 image load 期间使用：当前 Version 为 `0`；Flags 指定 preoptimized GC support 等
- `__objc_protolist` (`protocol_t *`)：Protocol list
- `__objc_nlcatlist` (`category_t`)：指向此 binary 中定义的 Non-Lazy Categories
- `__objc_catlist` (`category_t`)：指向此 binary 中定义的 Categories
- `__objc_nlclslist` (`classref_t`)：指向此 binary 中定义的 Non-Lazy Objective-C classes
- `__objc_classlist` (`classref_t`)：指向此 binary 中定义的所有 Objective-C classes

它还会使用 `__TEXT` segment 中的几个 sections 来存储 constants：

- `__objc_methname` (C-String)：Method names
- `__objc_classname` (C-String)：Class names
- `__objc_methtype` (C-String)：Method types

现代 macOS/iOS（尤其是在 Apple Silicon 上）还会将 Objective-C/Swift metadata 放置在：

- `__DATA_CONST`：可在进程之间以只读方式共享的 immutable Objective-C metadata（例如，许多 `__objc_*` lists 现在位于此处）。
- `__AUTH` / `__AUTH_CONST`：在 arm64e 上包含必须在 load 或 use-time 进行 authentication 的 pointers 的 segments（Pointer Authentication）。你还会在 `__AUTH_CONST` 中看到 `__auth_got`，而不只是 legacy `__la_symbol_ptr`/`__got`。进行 instrumenting 或 hooking 时，请记住在现代 binaries 中同时处理 `__got` 和 `__auth_got` entries。

有关 dyld pre-optimization 的背景信息（例如 selector uniquing 以及 class/protocol precomputation），以及为什么这些 sections 中的许多 sections 在来自 shared cache 时“已经完成 fix up”，请查看 Apple 的 `objc-opt` sources 和 dyld shared cache notes。这会影响你在 runtime patch metadata 的位置和方式。

{{#ref}}
../macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.md
{{#endref}}

### Type Encoding

Objective-C 使用 mangling 对简单和复杂类型的 selector 与 variable types 进行编码：

- Primitive types 使用其类型的首字母：`i` 表示 `int`，`c` 表示 `char`，`l` 表示 `long`……如果是 unsigned，则使用大写字母（`L` 表示 `unsigned long`）。
- 其他 data types 使用其他字母或符号，例如 `q` 表示 `long long`，`b` 表示 bitfields，`B` 表示 booleans，`#` 表示 classes，`@` 表示 `id`，`*` 表示 `char *`，`^` 表示 generic pointers，`?` 表示 undefined。
- Arrays、structures 和 unions 分别使用 `[`、`{` 和 `(`。

#### Example Method Declaration
```objectivec
- (NSString *)processString:(id)input withOptions:(char *)options andError:(id)error;
```
The selector would be `processString:withOptions:andError:`

#### Type Encoding

- `id` is encoded as `@`
- `char *` is encoded as `*`

The complete type encoding for the method is:
```less
@24@0:8@16*20^@24
```
#### 详细分解

1. 返回类型（`NSString *`）：编码为 `@`，长度为 24
2. `self`（对象实例）：编码为 `@`，偏移量为 0
3. `_cmd`（selector）：编码为 `:`，偏移量为 8
4. 第一个参数（`char * input`）：编码为 `*`，偏移量为 16
5. 第二个参数（`NSDictionary * options`）：编码为 `@`，偏移量为 20
6. 第三个参数（`NSError ** error`）：编码为 `^@`，偏移量为 24

结合 selector 和 encoding，即可重建该 method。

### Classes

Objective-C 中的 classes 是带有 properties、method pointers 等内容的 C structs。可以在[**源代码**](https://opensource.apple.com/source/objc4/objc4-756.2/runtime/objc-runtime-new.h.auto.html)中找到 `objc_class` struct：
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
此 class 使用 `isa` 字段中的某些位来表示有关该 class 的信息。

随后，该 struct 包含一个指向磁盘上存储的 struct `class_ro_t` 的指针，其中包含 class 的名称、基础 methods、properties 和 instance variables 等属性。在运行时还会使用一个额外的结构 `class_rw_t`，其中包含可修改的指针，例如 methods、protocols 和 properties。

{{#ref}}
../macos-basic-objective-c.md
{{#endref}}

---

## 内存中的现代 object 表示形式（arm64e、tagged pointers、Swift）

### Non‑pointer `isa` 和 Pointer Authentication（arm64e）

在 Apple Silicon 和较新的 runtime 中，Objective‑C `isa` 不一定是原始的 class pointer。在 arm64e 上，它是一种 packed structure，还可能携带 Pointer Authentication Code（PAC）。根据平台的不同，它可能包含 `nonpointer`、`has_assoc`、`weakly_referenced`、`extra_rc` 以及 class pointer 本身（经过移位或签名）等字段。这意味着，直接解引用 Objective‑C object 的前 8 个字节，并不总能得到有效的 `Class` pointer。<sup>[[2]](#references)</sup>

在 arm64e 上进行 debugging 时的实用注意事项：

- 使用 `po` 打印 Objective‑C objects 时，LLDB 通常会为你移除 PAC bits；但处理 raw pointers 时，可能需要手动移除 authentication：

```lldb
(lldb) expr -l objc++ -- #include <ptrauth.h>
(lldb) expr -l objc++ -- void *raw = ptrauth_strip((void*)0x000000016f123abc, ptrauth_key_asda);
(lldb) expr -l objc++ -O -- (Class)object_getClass((id)raw)
```

- Mach‑O 中的许多 function/data pointers 位于 `__AUTH`/`__AUTH_CONST` 中，使用前需要进行 authentication。如果你正在进行 interposing 或 re-binding（例如 fishhook-style），请确保同时处理 `__auth_got` 和传统的 `__got`。

如需深入了解 language/ABI guarantees 以及 Clang/LLVM 提供的 `<ptrauth.h>` intrinsics，请参阅本页末尾的 reference。<sup>[[1]](#references)</sup>

### Tagged pointer objects

一些 Foundation classes 会通过将 object 的 payload 直接编码到 pointer value 中来避免 heap allocation（tagged pointers）。检测方式因平台而异（例如，在 arm64 上使用 most-significant bit，在 x86_64 macOS 上使用 least-significant bit）。Tagged objects 不会在内存中存储常规的 `isa`；runtime 会根据 tag bits 解析 class。<sup>[[2]](#references)</sup> 检查任意 `id` values 时：

- 使用 runtime APIs，而不是直接读取 `isa` field：`object_getClass(obj)` / `[obj class]`。
- 在 LLDB 中，直接执行 `po (id)0xADDR` 即可正确打印 tagged pointer instances，因为 runtime 会参与 class 解析。

### Swift heap objects 和 metadata

纯 Swift classes 同样是 objects，其 header 指向 Swift metadata，而不是 Objective‑C `isa`。若要在不修改 live Swift processes 的情况下进行 introspection，可以使用 Swift toolchain 的 `swift-inspect`，它借助 Remote Mirror library 读取 runtime metadata：
```bash
# Xcode toolchain (or Swift.org toolchain) provides swift-inspect
swift-inspect dump-raw-metadata <pid-or-name>
swift-inspect dump-arrays <pid-or-name>
# On Darwin additionally:
swift-inspect dump-concurrency <pid-or-name>
```
这对于在逆向 mixed Swift/ObjC apps 时映射 Swift heap objects 和 protocol conformances 非常有用。

---

## Runtime inspection cheatsheet（LLDB / Frida）

### LLDB

- 从 raw pointer 打印 object 或 class：
```lldb
(lldb) expr -l objc++ -O -- (id)0x0000000101234560
(lldb) expr -l objc++ -O -- (Class)object_getClass((id)0x0000000101234560)
```
- 在断点处通过对象方法的 `self` 指针检查 Objective-C 类：
```lldb
(lldb) br se -n '-[NSFileManager fileExistsAtPath:]'
(lldb) r
... breakpoint hit ...
(lldb) po (id)$x0                 # self
(lldb) expr -l objc++ -O -- (Class)object_getClass((id)$x0)
```
- Dump 包含 Objective-C metadata 的 sections（注意：其中许多现在位于 `__DATA_CONST` / `__AUTH_CONST`）：
```lldb
(lldb) image dump section --section __DATA_CONST.__objc_classlist
(lldb) image dump section --section __DATA_CONST.__objc_selrefs
(lldb) image dump section --section __AUTH_CONST.__auth_got
```
- 读取已知 class object 的内存，以便在逆向 method lists 时 pivot 到 `class_ro_t` / `class_rw_t`：
```lldb
(lldb) image lookup -r -n _OBJC_CLASS_$_NSFileManager
(lldb) memory read -fx -s8 0xADDRESS_OF_CLASS_OBJECT
```
### Frida（Objective-C 和 Swift）

Frida 提供了高级 runtime bridge，非常适合在没有 symbols 的情况下发现并 instrument 运行中的 objects：

- 枚举 classes 和 methods，在 runtime 解析实际的 class names，并拦截 Objective-C selectors：
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
- Swift bridge：枚举 Swift 类型并与 Swift instances 交互（需要较新的 Frida；对 Apple Silicon targets 非常有用）。

---

## References

- [1] [Clang/LLVM：Pointer Authentication 和 ptrauth.h intrinsics（arm64e ABI）](https://clang.llvm.org/docs/PointerAuthentication.html)
- [2] [Apple objc runtime headers - objc-object.h（tagged pointers、non-pointer isa 等）](https://opensource.apple.com/source/objc4/objc4-818.2/runtime/objc-object.h.auto.html)

{{#include ../../../banners/hacktricks-training.md}}
