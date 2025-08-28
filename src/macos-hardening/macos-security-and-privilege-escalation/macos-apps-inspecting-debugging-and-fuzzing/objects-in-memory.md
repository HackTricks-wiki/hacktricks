# Objects in memory

{{#include ../../../banners/hacktricks-training.md}}

## CFRuntimeClass

CF* objects come from CoreFoundation, which provides more than 50 classes of objects like `CFString`, `CFNumber` or `CFAllocator`.

All these classes are instances of the class `CFRuntimeClass`, which when called it returns an index to the `__CFRuntimeClassTable`. The CFRuntimeClass is defined in [**CFRuntime.h**](https://opensource.apple.com/source/CF/CF-1153.18/CFRuntime.h.auto.html):

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

- `__objc_msgrefs` (`message_ref_t`): Message references
- `__objc_ivar` (`ivar`): Instance variables
- `__objc_data` (`...`): Mutable data
- `__objc_classrefs` (`Class`): Class references
- `__objc_superrefs` (`Class`): Superclass references
- `__objc_protorefs` (`protocol_t *`): Protocol references
- `__objc_selrefs` (`SEL`): Selector references
- `__objc_const` (`...`): Class r/o data and other (hopefully) constant data
- `__objc_imageinfo` (`version, flags`): Used during image load: Version currently `0`; Flags specify preoptimized GC support, etc.
- `__objc_protolist` (`protocol_t *`): Protocol list
- `__objc_nlcatlist` (`category_t`): Pointer to Non-Lazy Categories defined in this binary
- `__objc_catlist` (`category_t`): Pointer to Categories defined in this binary
- `__objc_nlclslist` (`classref_t`): Pointer to Non-Lazy Objective‑C classes defined in this binary
- `__objc_classlist` (`classref_t`): Pointers to all Objective‑C classes defined in this binary

It also uses a few sections in the `__TEXT` segment to store constants:

- `__objc_methname` (C‑String): Method names
- `__objc_classname` (C‑String): Class names
- `__objc_methtype` (C‑String): Method types

Modern macOS/iOS (especially on Apple Silicon) also place Objective‑C/Swift metadata in:

- `__DATA_CONST`: immutable Objective‑C metadata that can be shared read‑only across processes (for example many `__objc_*` lists now live here).
- `__AUTH` / `__AUTH_CONST`: segments containing pointers that must be authenticated at load or use‑time on arm64e (Pointer Authentication). You will also see `__auth_got` in `__AUTH_CONST` instead of the legacy `__la_symbol_ptr`/`__got` only. When instrumenting or hooking, remember to account for both `__got` and `__auth_got` entries in modern binaries.

For background on dyld pre‑optimization (e.g., selector uniquing and class/protocol precomputation) and why many of these sections are "already fixed up" when coming from the shared cache, check the Apple `objc-opt` sources and dyld shared cache notes. This affects where and how you can patch metadata at runtime.

{{#ref}}
../macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.md
{{#endref}}

### Type Encoding

Objective‑C uses mangling to encode selector and variable types of simple and complex types:

- Primitive types use their first letter of the type `i` for `int`, `c` for `char`, `l` for `long`... and use the capital letter in case it's unsigned (`L` for `unsigned long`).
- Other data types use other letters or symbols like `q` for `long long`, `b` for bitfields, `B` for booleans, `#` for classes, `@` for `id`, `*` for `char *`, `^` for generic pointers and `?` for undefined.
- Arrays, structures and unions use `[`, `{` and `(` respectively.

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

#### Detailed Breakdown

1. Return Type (`NSString *`): Encoded as `@` with length 24
2. `self` (object instance): Encoded as `@`, at offset 0
3. `_cmd` (selector): Encoded as `:`, at offset 8
4. First argument (`char * input`): Encoded as `*`, at offset 16
5. Second argument (`NSDictionary * options`): Encoded as `@`, at offset 20
6. Third argument (`NSError ** error`): Encoded as `^@`, at offset 24

With the selector + the encoding you can reconstruct the method.

### Classes

Classes in Objective‑C are C structs with properties, method pointers, etc. It's possible to find the struct `objc_class` in the [**source code**](https://opensource.apple.com/source/objc4/objc4-756.2/runtime/objc-runtime-new.h.auto.html):

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

## Modern object representations in memory (arm64e, tagged pointers, Swift)

### Non‑pointer `isa` and Pointer Authentication (arm64e)

On Apple Silicon and recent runtimes the Objective‑C `isa` is not always a raw class pointer. On arm64e it is a packed structure that may also carry a Pointer Authentication Code (PAC). Depending on the platform it may include fields like `nonpointer`, `has_assoc`, `weakly_referenced`, `extra_rc`, and the class pointer itself (shifted or signed). This means blindly dereferencing the first 8 bytes of an Objective‑C object will not always yield a valid `Class` pointer.

Practical notes when debugging on arm64e:

- LLDB will usually strip PAC bits for you when printing Objective‑C objects with `po`, but when working with raw pointers you may need to strip authentication manually:
  
  ```lldb
  (lldb) expr -l objc++ -- #include <ptrauth.h>
  (lldb) expr -l objc++ -- void *raw = ptrauth_strip((void*)0x000000016f123abc, ptrauth_key_asda);
  (lldb) expr -l objc++ -O -- (Class)object_getClass((id)raw)
  ```

- Many function/data pointers in Mach‑O will reside in `__AUTH`/`__AUTH_CONST` and require authentication before use. If you are interposing or re‑binding (e.g., fishhook‑style), ensure you also handle `__auth_got` in addition to legacy `__got`.

For a deep dive into language/ABI guarantees and the `<ptrauth.h>` intrinsics available from Clang/LLVM, see the reference in the end of this page.

### Tagged pointer objects

Some Foundation classes avoid heap allocation by encoding the object’s payload directly in the pointer value (tagged pointers). Detection differs by platform (e.g., the most‑significant bit on arm64, least‑significant on x86_64 macOS). Tagged objects don’t have a regular `isa` stored in memory; the runtime resolves the class from the tag bits. When inspecting arbitrary `id` values:

- Use runtime APIs instead of poking the `isa` field: `object_getClass(obj)` / `[obj class]`.
- In LLDB, just `po (id)0xADDR` will print tagged pointer instances correctly because the runtime is consulted to resolve the class.

### Swift heap objects and metadata

Pure Swift classes are also objects with a header pointing to Swift metadata (not Objective‑C `isa`). To introspect live Swift processes without modifying them you can use the Swift toolchain’s `swift-inspect`, which leverages the Remote Mirror library to read runtime metadata:

```bash
# Xcode toolchain (or Swift.org toolchain) provides swift-inspect
swift-inspect dump-raw-metadata <pid-or-name>
swift-inspect dump-arrays <pid-or-name>
# On Darwin additionally:
swift-inspect dump-concurrency <pid-or-name>
```

This is very useful to map Swift heap objects and protocol conformances when reversing mixed Swift/ObjC apps.

---

## Runtime inspection cheatsheet (LLDB / Frida)

### LLDB

- Print object or class from a raw pointer:

```lldb
(lldb) expr -l objc++ -O -- (id)0x0000000101234560
(lldb) expr -l objc++ -O -- (Class)object_getClass((id)0x0000000101234560)
```

- Inspect Objective‑C class from a pointer to an object method’s `self` in a breakpoint:

```lldb
(lldb) br se -n '-[NSFileManager fileExistsAtPath:]'
(lldb) r
... breakpoint hit ...
(lldb) po (id)$x0                 # self
(lldb) expr -l objc++ -O -- (Class)object_getClass((id)$x0)
```

- Dump sections that carry Objective‑C metadata (note: many are now in `__DATA_CONST` / `__AUTH_CONST`):

```lldb
(lldb) image dump section --section __DATA_CONST.__objc_classlist
(lldb) image dump section --section __DATA_CONST.__objc_selrefs
(lldb) image dump section --section __AUTH_CONST.__auth_got
```

- Read memory for a known class object to pivot to `class_ro_t` / `class_rw_t` when reversing method lists:

```lldb
(lldb) image lookup -r -n _OBJC_CLASS_$_NSFileManager
(lldb) memory read -fx -s8 0xADDRESS_OF_CLASS_OBJECT
```

### Frida (Objective‑C and Swift)

Frida provides high‑level runtime bridges that are very handy to discover and instrument live objects without symbols:

- Enumerate classes and methods, resolve actual class names at runtime, and intercept Objective‑C selectors:

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

- Swift bridge: enumerate Swift types and interact with Swift instances (requires recent Frida; very useful on Apple Silicon targets).

---

## References

- Clang/LLVM: Pointer Authentication and the `<ptrauth.h>` intrinsics (arm64e ABI). https://clang.llvm.org/docs/PointerAuthentication.html
- Apple objc runtime headers (tagged pointers, non‑pointer `isa`, etc.) e.g., `objc-object.h`. https://opensource.apple.com/source/objc4/objc4-818.2/runtime/objc-object.h.auto.html

{{#include ../../../banners/hacktricks-training.md}}
