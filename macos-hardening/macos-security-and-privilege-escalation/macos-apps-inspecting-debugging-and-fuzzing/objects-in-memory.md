# Objects in memory

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

## CFRuntimeClass

CF\* objects come from CoreFOundation, which provides more than 50 classes of objects like `CFString`, `CFNumber` or `CFAllocatior`.

All these clases are instances of the class `CFRuntimeClass`, which when called it returns an index to the `__CFRuntimeClassTable`. The CFRuntimeClass is defined in [**CFRuntime.h**](https://opensource.apple.com/source/CF/CF-1153.18/CFRuntime.h.auto.html):

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

Most of the data used by ObjectiveC runtime will change during the execution, therefore it uses some sections from the **\_\_DATA** segment in memory:

* **`__objc_msgrefs`** (`message_ref_t`): Message references
* **`__objc_ivar`** (`ivar`): Instance variables
* **`__objc_data`** (`...`): Mutable data
* **`__objc_classrefs`** (`Class`): Class references
* **`__objc_superrefs`** (`Class`): Superclass references
* **`__objc_protorefs`** (`protocol_t *`): Protocol references
* **`__objc_selrefs`** (`SEL`): Selector references
* **`__objc_const`** (`...`): Class `r/o` data and other (hopefully) constant data
* **`__objc_imageinfo`** (`version, flags`): Used during image load: Version currently `0`; Flags specify preoptimized GC support, etc.
* **`__objc_protolist`** (`protocol_t *`): Protocol list
* **`__objc_nlcatlist`** (`category_t`): Pointer to Non-Lazy Categories defined in this binary
* **`__objc_catlist`** (`category_t`): Pointer to Categories defined in this binary
* **`__objc_nlclslist`** (`classref_t`): Pointer to Non-Lazy Objective-C classes defined in this binary
* **`__objc_classlist`** (`classref_t`): Pointers to all Objective-C classes defined in this binary

It also uses a few sections in the **`__TEXT`** segment to store constan values of it's not possible to write in this section:

* **`__objc_methname`** (C-String): Method names
* **`__objc_classname`** (C-String): Class names
* **`__objc_methtype`** (C-String): Method types

### Type Encoding

Objective-c uses some mangling to encode selector and variable types of simple and complex types:

* Primitive types use their first letter of the type `i` for `int`, `c` for `char`, `l` for `long`... and uses the capital letter in case it's unsigned (`L` for `unsigned Long`).
* Other data types whose letters are used or are special, use other letters or symbols like `q` for `long long`, `b` for `bitfields`, `B` for `booleans`, `#` for `classes`, `@` for `id`, `*` for `char pointers` , `^` for generic `pointers` and `?` for `undefined`.
* Arrays, structures and unions use `[`, `{` and `(`

#### Example Method Declaration

{% code overflow="wrap" %}
```objectivec
- (NSString *)processString:(id)input withOptions:(char *)options andError:(id)error;
```
{% endcode %}

The selector would be `processString:withOptions:andError:`

#### Type Encoding

* `id` is encoded as `@`
* `char *` is encoded as `*`

The complete type encoding for the method is:

```less
@24@0:8@16*20^@24
```

#### Detailed Breakdown

1. **Return Type (`NSString *`)**: Encoded as `@` with length 24
2. **`self` (object instance)**: Encoded as `@`, at offset 0
3. **`_cmd` (selector)**: Encoded as `:`, at offset 8
4. **First argument (`char * input`)**: Encoded as `*`, at offset 16
5. **Second argument (`NSDictionary * options`)**: Encoded as `@`, at offset 20
6. **Third argument (`NSError ** error`)**: Encoded as `^@`, at offset 24

**With the selector + the encoding you can reconstruct the method.**

### **Classes**

Clases in Objective-C is a struct with properties, method pointers... It's possible to find the struct `objc_class` in the [**source code**](https://opensource.apple.com/source/objc4/objc4-756.2/runtime/objc-runtime-new.h.auto.html):

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

This class use some bits of the isa field to indicate some information about the class.

Then, the struct has a pointer to the struct `class_ro_t` stored on disk which contains attributes of the class like its name, base methods, properties and instance variables.\
During runtime and additional structure `class_rw_t` is used containing pointers which can be altered such as methods, protocols, properties...



{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

