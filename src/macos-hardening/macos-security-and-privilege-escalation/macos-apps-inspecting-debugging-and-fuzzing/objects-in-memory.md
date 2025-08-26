# 内存中的对象

{{#include ../../../banners/hacktricks-training.md}}

## CFRuntimeClass

CF* 对象来自 CoreFoundation，后者提供了超过 50 种对象类，例如 `CFString`、`CFNumber` 或 `CFAllocator`。

所有这些类都是类 `CFRuntimeClass` 的实例，其在被调用时会返回 `__CFRuntimeClassTable` 的索引。CFRuntimeClass 在 [**CFRuntime.h**](https://opensource.apple.com/source/CF/CF-1153.18/CFRuntime.h.auto.html) 中定义：
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

Most of the data used by Objective‑C runtime will change during execution, therefore it uses a number of sections from the Mach‑O `__DATA` family of segments in memory. Historically these included:

- `__objc_msgrefs` (`message_ref_t`): 消息引用
- `__objc_ivar` (`ivar`): 实例变量
- `__objc_data` (`...`): 可变数据
- `__objc_classrefs` (`Class`): 类引用
- `__objc_superrefs` (`Class`): 超类引用
- `__objc_protorefs` (`protocol_t *`): 协议引用
- `__objc_selrefs` (`SEL`): selector 引用
- `__objc_const` (`...`): 类只读数据和其他（希望是）常量数据
- `__objc_imageinfo` (`version, flags`): 在镜像加载期间使用：当前 Version 为 `0`；Flags 指定预优化的 GC 支持等
- `__objc_protolist` (`protocol_t *`): 协议列表
- `__objc_nlcatlist` (`category_t`): 指向此二进制中定义的 Non-Lazy Categories 的指针
- `__objc_catlist` (`category_t`): 指向此二进制中定义的 Categories 的指针
- `__objc_nlclslist` (`classref_t`): 指向此二进制中定义的 Non-Lazy Objective‑C classes 的指针
- `__objc_classlist` (`classref_t`): 指向此二进制中定义的所有 Objective‑C classes 的指针

它还使用 `__TEXT` 段中的几个节来存储常量：

- `__objc_methname` (C‑String): 方法名
- `__objc_classname` (C‑String): 类名
- `__objc_methtype` (C‑String): 方法类型

现代 macOS/iOS（尤其是 Apple Silicon 上）还将 Objective‑C/Swift 元数据放在：

- `__DATA_CONST`: 不可变的 Objective‑C 元数据，可以跨进程以只读方式共享（例如许多 `__objc_*` 列表现在存放在这里）。
- `__AUTH` / `__AUTH_CONST`: 包含在 arm64e 上于加载或使用时必须进行认证的指针（Pointer Authentication）的段。你还会在 `__AUTH_CONST` 中看到 `__auth_got`，而不是仅有的传统 `__la_symbol_ptr`/`__got`。在进行 instrumenting 或 hooking 时，记得要同时考虑现代二进制中的 `__got` 和 `__auth_got` 条目。

For background on dyld pre‑optimization (e.g., selector uniquing and class/protocol precomputation) and why many of these sections are "already fixed up" when coming from the shared cache, check the Apple `objc-opt` sources and dyld shared cache notes. This affects where and how you can patch metadata at runtime.

{{#ref}}
../macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.md
{{#endref}}

### Type Encoding

Objective‑C uses mangling to encode selector and variable types of simple and complex types:

- Primitive types use their first letter of the type `i` for `int`, `c` for `char`, `l` for `long`... and use the capital letter in case it's unsigned (`L` for `unsigned long`).
- Other data types use other letters or symbols like `q` for `long long`, `b` for 位域, `B` for 布尔值, `#` for 类, `@` for `id`, `*` for `char *`, `^` for 通用指针 and `?` for undefined.
- Arrays, structures and unions use `[`, `{` and `(` respectively.

#### Example Method Declaration
```objectivec
- (NSString *)processString:(id)input withOptions:(char *)options andError:(id)error;
```
selector 将会是 `processString:withOptions:andError:`

#### 类型编码

- `id` 被编码为 `@`
- `char *` 被编码为 `*`

该方法的完整类型编码为：
```less
@24@0:8@16*20^@24
```
#### 详细分解

1. 返回类型 (`NSString *`)：编码为 `@`，长度为 24
2. `self`（对象实例）：编码为 `@`，偏移量为 0
3. `_cmd`（选择子）：编码为 `:`，偏移量为 8
4. 第一个参数 (`char * input`)：编码为 `*`，偏移量为 16
5. 第二个参数 (`NSDictionary * options`)：编码为 `@`，偏移量为 20
6. 第三个参数 (`NSError ** error`)：编码为 `^@`，偏移量为 24

通过选择子和编码，你可以重建该方法。

### 类

Objective‑C 中的类是具有属性、方法指针等的 C 结构体。可以在 [**source code**](https://opensource.apple.com/source/objc4/objc4-756.2/runtime/objc-runtime-new.h.auto.html) 中找到 struct `objc_class`：
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
这个类使用 `isa` 字段的一些位来表示关于类的信息。

然后，该 struct 有一个指向存储在磁盘上的 `class_ro_t` 结构的指针，后者包含类的属性，例如名称、base methods、properties 和实例变量。在运行时，还会使用一个额外的 `class_rw_t` 结构来保存可被修改的指针，例如 methods、protocols、properties。

{{#ref}}
../macos-basic-objective-c.md
{{#endref}}

---

## 内存中的现代对象表示 (arm64e, tagged pointers, Swift)

### 非指针 `isa` 与指针认证 (arm64e)

在 Apple Silicon 和较新的运行时中，Objective‑C 的 `isa` 并不总是一个原始的类指针。在 arm64e 上，它是一个打包结构，可能还携带 Pointer Authentication Code (PAC)。根据平台不同，它可能包含诸如 `nonpointer`、`has_assoc`、`weakly_referenced`、`extra_rc` 等字段，以及类指针本身（可能被移位或带符号）。这意味着盲目地解引用 Objective‑C 对象的前 8 个字节并不总能得到有效的 `Class` 指针。

在 arm64e 上调试时的实用注意事项：

- LLDB 在使用 `po` 打印 Objective‑C 对象时通常会为你去除 PAC 位，但在处理原始指针时可能需要手动去除认证：

```lldb
(lldb) expr -l objc++ -- #include <ptrauth.h>
(lldb) expr -l objc++ -- void *raw = ptrauth_strip((void*)0x000000016f123abc, ptrauth_key_asda);
(lldb) expr -l objc++ -O -- (Class)object_getClass((id)raw)
```

- Mach‑O 中的许多函数/数据指针会位于 `__AUTH`/`__AUTH_CONST`，在使用前需要进行认证。如果你在进行 interposing 或 re‑binding（例如 fishhook‑style），请确保除了传统的 `__got` 之外也处理 `__auth_got`。

有关语言/ABI 保证以及 Clang/LLVM 提供的 `<ptrauth.h>` intrinsics 的深入解析，请参见本页末尾的参考资料。

### Tagged pointer 对象

一些 Foundation 类通过将对象的有效载荷直接编码在指针值中来避免堆分配（tagged pointers）。不同平台的检测方式不同（例如在 arm64 上是最高有效位，而在 x86_64 macOS 上是最低有效位）。tagged 对象在内存中没有常规的 `isa`；运行时会通过 tag 位解析类。在检查任意 `id` 值时：

- 使用运行时 API，而不是直接探查 `isa` 字段：`object_getClass(obj)` / `[obj class]`。
- 在 LLDB 中，直接 `po (id)0xADDR` 会正确打印 tagged pointer 实例，因为会咨询运行时以解析类。

### Swift 堆对象与元数据

纯 Swift 类也是对象，其头部指向 Swift 元数据（而不是 Objective‑C 的 `isa`）。要在不修改进程的情况下检查运行中的 Swift 进程，可以使用 Swift toolchain 的 `swift-inspect`，它利用 Remote Mirror 库来读取运行时元数据：
```bash
# Xcode toolchain (or Swift.org toolchain) provides swift-inspect
swift-inspect dump-raw-metadata <pid-or-name>
swift-inspect dump-arrays <pid-or-name>
# On Darwin additionally:
swift-inspect dump-concurrency <pid-or-name>
```
在对混合 Swift/ObjC 应用进行逆向时，这对于映射 Swift 堆对象和协议遵从性非常有用。

---

## 运行时检查速查表 (LLDB / Frida)

### LLDB

- 从原始指针打印对象或类：
```lldb
(lldb) expr -l objc++ -O -- (id)0x0000000101234560
(lldb) expr -l objc++ -O -- (Class)object_getClass((id)0x0000000101234560)
```
- 在 breakpoint 中，从指向对象方法的 `self` 的指针检查 Objective‑C class:
```lldb
(lldb) br se -n '-[NSFileManager fileExistsAtPath:]'
(lldb) r
... breakpoint hit ...
(lldb) po (id)$x0                 # self
(lldb) expr -l objc++ -O -- (Class)object_getClass((id)$x0)
```
- 转储携带 Objective‑C 元数据的节（注意：许多现在位于 `__DATA_CONST` / `__AUTH_CONST`）：
```lldb
(lldb) image dump section --section __DATA_CONST.__objc_classlist
(lldb) image dump section --section __DATA_CONST.__objc_selrefs
(lldb) image dump section --section __AUTH_CONST.__auth_got
```
- 读取已知类对象的内存以在反向工程方法列表时转向 `class_ro_t` / `class_rw_t`:
```lldb
(lldb) image lookup -r -n _OBJC_CLASS_$_NSFileManager
(lldb) memory read -fx -s8 0xADDRESS_OF_CLASS_OBJECT
```
### Frida (Objective‑C and Swift)

Frida 提供高级的运行时桥接，非常适合在没有符号的情况下发现并对实时对象进行插桩：

- 枚举类和方法，在运行时解析实际类名，并拦截 Objective‑C 选择器：
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
- Swift bridge: 枚举 Swift 类型并与 Swift 实例交互（需要较新的 Frida；在 Apple Silicon 目标上非常有用）。

---

## 参考资料

- Clang/LLVM: Pointer Authentication and the `<ptrauth.h>` intrinsics (arm64e ABI). https://clang.llvm.org/docs/PointerAuthentication.html
- Apple objc 运行时头文件（tagged pointers、non‑pointer `isa` 等），例如 `objc-object.h`. https://opensource.apple.com/source/objc4/objc4-818.2/runtime/objc-object.h.auto.html

{{#include ../../../banners/hacktricks-training.md}}
