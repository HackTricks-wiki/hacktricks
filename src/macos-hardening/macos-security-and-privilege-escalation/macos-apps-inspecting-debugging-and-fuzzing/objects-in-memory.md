# メモリ内のオブジェクト

{{#include ../../../banners/hacktricks-training.md}}

## CFRuntimeClass

CF* オブジェクトは CoreFoundation に由来し、`CFString`、`CFNumber`、`CFAllocator` など、50 を超えるクラスのオブジェクトを提供します。

これらすべてのクラスは `CFRuntimeClass` クラスのインスタンスです。これを呼び出すと、`__CFRuntimeClassTable` へのインデックスが返されます。CFRuntimeClass は [**CFRuntime.h**](https://opensource.apple.com/source/CF/CF-1153.18/CFRuntime.h.auto.html) で定義されています：
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

### 使用される Memory sections

Objective-C runtimeで使用されるデータの大部分は実行中に変化するため、メモリ上のMach-O `__DATA` familyのsegmentに含まれる複数のsectionを使用します。従来、これらには次のものが含まれていました。

- `__objc_msgrefs` (`message_ref_t`): Message references
- `__objc_ivar` (`ivar`): Instance variables
- `__objc_data` (`...`): Mutable data
- `__objc_classrefs` (`Class`): Class references
- `__objc_superrefs` (`Class`): Superclass references
- `__objc_protorefs` (`protocol_t *`): Protocol references
- `__objc_selrefs` (`SEL`): Selector references
- `__objc_const` (`...`): Class r/o dataおよびその他の（期待される）constant data
- `__objc_imageinfo` (`version, flags`): image load中に使用されます。現在のVersionは`0`です。Flagsはpreoptimized GC supportなどを指定します。
- `__objc_protolist` (`protocol_t *`): Protocol list
- `__objc_nlcatlist` (`category_t`): このbinaryで定義されたNon-Lazy CategoriesへのPointer
- `__objc_catlist` (`category_t`): このbinaryで定義されたCategoriesへのPointer
- `__objc_nlclslist` (`classref_t`): このbinaryで定義されたNon-Lazy Objective-C classesへのPointer
- `__objc_classlist` (`classref_t`): このbinaryで定義されたすべてのObjective-C classesへのPointer

また、constantsを格納するために、`__TEXT` segment内のいくつかのsectionも使用します。

- `__objc_methname` (C‑String): Method names
- `__objc_classname` (C‑String): Class names
- `__objc_methtype` (C‑String): Method types

Modern macOS/iOS（特にApple Silicon）では、Objective-C/Swift metadataも次の場所に配置されます。

- `__DATA_CONST`: immutableなObjective-C metadata。process間でread-onlyとして共有できます（たとえば、多くの`__objc_*` listsが現在ここに配置されています）。
- `__AUTH` / `__AUTH_CONST`: arm64e上でload時またはuse-timeにauthenticationが必要なpointers（Pointer Authentication）を含むsegments。legacyの`__la_symbol_ptr`/`__got`だけでなく、`__AUTH_CONST`内の`__auth_got`も確認できます。instrumentingやhookingを行う場合は、modern binariesにおける`__got`と`__auth_got`の両方のentriesを考慮してください。

dyld pre-optimization（selector uniquingやclass/protocol precomputationなど）の背景、およびshared cache由来の場合にこれらのsectionsの多くが「すでにfixed up」されている理由については、Appleの`objc-opt` sourcesとdyld shared cache notesを確認してください。これは、runtimeでmetadataをpatchできる場所と方法に影響します。

{{#ref}}
../macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.md
{{#endref}}

### Type Encoding

Objective-Cでは、simple typesとcomplex typesのselectorおよびvariable typesをencodeするために、manglingを使用します。

- Primitive typesはtypeの最初のletterを使用します。`int`には`i`、`char`には`c`、`long`には`l`などを使用し、unsignedの場合はcapital letterを使用します（`unsigned long`には`L`）。
- その他のdata typesでは、`long long`を表す`q`、bitfieldsを表す`b`、booleansを表す`B`、classesを表す`#`、`id`を表す`@`、`char *`を表す`*`、generic pointersを表す`^`、undefinedを表す`?`など、その他のlettersまたはsymbolsを使用します。
- Arrays、structures、unionsには、それぞれ`[`、`{`、`(`を使用します。

#### Example Method Declaration
```objectivec
- (NSString *)processString:(id)input withOptions:(char *)options andError:(id)error;
```
セレクタは `processString:withOptions:andError:` になります。

#### Type Encoding

- `id` は `@` としてエンコードされます
- `char *` は `*` としてエンコードされます

このメソッドの完全な型エンコーディングは次のとおりです。
```less
@24@0:8@16*20^@24
```
#### 詳細な内訳

1. Return Type (`NSString *`): `@` としてエンコードされ、長さは 24
2. `self`（object instance）: `@` としてエンコードされ、offset は 0
3. `_cmd`（selector）: `:` としてエンコードされ、offset は 8
4. First argument (`char * input`): `*` としてエンコードされ、offset は 16
5. Second argument (`NSDictionary * options`): `@` としてエンコードされ、offset は 20
6. Third argument (`NSError ** error`): `^@` としてエンコードされ、offset は 24

selector と encoding を使用すると、method を再構築できます。

### Classes

Objective-C の Classes は、properties、method pointers などを持つ C structs です。`objc_class` struct は、[**source code**](https://opensource.apple.com/source/objc4/objc4-756.2/runtime/objc-runtime-new.h.auto.html) で確認できます：
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
この class は `isa` field の一部を使用して、class に関する情報を示します。

その後、struct にはディスク上に保存された struct `class_ro_t` への pointer があり、class の name、base methods、properties、instance variables などの属性が含まれています。runtime 中は、methods、protocols、properties など、変更可能な pointer を含む追加の structure `class_rw_t` が使用されます。

{{#ref}}
../macos-basic-objective-c.md
{{#endref}}

---

## メモリ上の Modern object representations（arm64e、tagged pointers、Swift）

### Non-pointer `isa` と Pointer Authentication（arm64e）

Apple Silicon および recent runtimes では、Objective-C `isa` は常に raw class pointer であるとは限りません。arm64e では packed structure であり、Pointer Authentication Code（PAC）も保持する場合があります。platform によっては、`nonpointer`、`has_assoc`、`weakly_referenced`、`extra_rc`、および class pointer 自体（shift または signed されたもの）などの field が含まれます。そのため、Objective-C object の最初の 8 bytes を無条件に dereference しても、常に有効な `Class` pointer が得られるとは限りません。<sup>[[2]](#references)</sup>

arm64e で debugging する際の実用的な注意点：

- Objective-C objects を `po` で print すると、通常 LLDB が PAC bits を strip してくれます。ただし raw pointers を扱う場合は、authentication を手動で strip する必要があります：

```lldb
(lldb) expr -l objc++ -- #include <ptrauth.h>
(lldb) expr -l objc++ -- void *raw = ptrauth_strip((void*)0x000000016f123abc, ptrauth_key_asda);
(lldb) expr -l objc++ -O -- (Class)object_getClass((id)raw)
```

- Mach-O 内の多くの function/data pointers は `__AUTH`/`__AUTH_CONST` に配置され、使用前に authentication が必要です。interposing または re-binding（fishhook-style など）を行う場合は、従来の `__got` に加えて `__auth_got` も処理するようにしてください。

language/ABI の guarantees と、Clang/LLVM で利用可能な `<ptrauth.h>` intrinsics の詳細については、この page の末尾にある reference を参照してください。<sup>[[1]](#references)</sup>

### Tagged pointer objects

一部の Foundation classes は、object の payload を pointer value に直接 encode することで、heap allocation を回避します（tagged pointers）。検出方法は platform によって異なります（例：arm64 では most-significant bit、x86_64 macOS では least-significant bit）。Tagged objects には通常の `isa` が memory に保存されておらず、runtime が tag bits から class を解決します。<sup>[[2]](#references)</sup> 任意の `id` values を inspect する場合：

- `isa` field を直接調べるのではなく、runtime APIs を使用します：`object_getClass(obj)` / `[obj class]`。
- LLDB では、`po (id)0xADDR` を実行するだけで tagged pointer instances が正しく print されます。これは runtime が class の解決に使用されるためです。

### Swift heap objects と metadata

Pure Swift classes も objects であり、Objective-C `isa` ではなく Swift metadata を指す header を持ちます。process を変更せずに live Swift processes を introspect するには、Swift toolchain の `swift-inspect` を使用できます。これは Remote Mirror library を利用して runtime metadata を読み取ります：
```bash
# Xcode toolchain (or Swift.org toolchain) provides swift-inspect
swift-inspect dump-raw-metadata <pid-or-name>
swift-inspect dump-arrays <pid-or-name>
# On Darwin additionally:
swift-inspect dump-concurrency <pid-or-name>
```
Swift/ObjC 混在アプリを reverse する際に、Swift heap objects と protocol conformances を map するのに非常に役立ちます。

---

## Runtime inspection cheatsheet (LLDB / Frida)

### LLDB

- raw pointer から object または class を表示する：
```lldb
(lldb) expr -l objc++ -O -- (id)0x0000000101234560
(lldb) expr -l objc++ -O -- (Class)object_getClass((id)0x0000000101234560)
```
- ブレークポイントで、オブジェクトメソッドの `self` へのポインターから Objective-C class を調査する:
```lldb
(lldb) br se -n '-[NSFileManager fileExistsAtPath:]'
(lldb) r
... breakpoint hit ...
(lldb) po (id)$x0                 # self
(lldb) expr -l objc++ -O -- (Class)object_getClass((id)$x0)
```
- Objective-C メタデータを含む section を Dump する（注: 現在は多くが `__DATA_CONST` / `__AUTH_CONST` に存在します）:
```lldb
(lldb) image dump section --section __DATA_CONST.__objc_classlist
(lldb) image dump section --section __DATA_CONST.__objc_selrefs
(lldb) image dump section --section __AUTH_CONST.__auth_got
```
- 既知のクラスオブジェクトのメモリを読み取り、method listをreverseする際に`class_ro_t` / `class_rw_t`へpivotする：
```lldb
(lldb) image lookup -r -n _OBJC_CLASS_$_NSFileManager
(lldb) memory read -fx -s8 0xADDRESS_OF_CLASS_OBJECT
```
### Frida (Objective-C および Swift)

Frida は、symbols なしで実行中のオブジェクトを発見・instrumentation するのに非常に便利な、高レベルの runtime bridge を提供します。

- クラスとメソッドを列挙し、runtime で実際のクラス名を解決し、Objective-C selector を intercept します:
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
- Swift bridge: Swift types を列挙し、Swift instances と対話する（recent Frida が必要。Apple Silicon targets で非常に有用）。

---

## References


- [1] [Clang/LLVM: Pointer Authentication と ptrauth.h intrinsics（arm64e ABI）](https://clang.llvm.org/docs/PointerAuthentication.html)
- [2] [Apple objc runtime headers - objc-object.h（tagged pointers、non-pointer isa など）](https://opensource.apple.com/source/objc4/objc4-818.2/runtime/objc-object.h.auto.html)

{{#include ../../../banners/hacktricks-training.md}}
