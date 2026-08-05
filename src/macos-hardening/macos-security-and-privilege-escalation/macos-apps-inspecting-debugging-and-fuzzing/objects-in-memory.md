# メモリ内のオブジェクト

{{#include ../../../banners/hacktricks-training.md}}

## CFRuntimeClass

CF* objects は CoreFoundation に由来し、`CFString`、`CFNumber`、`CFAllocator` など、50 種類を超えるオブジェクトのクラスを提供します。

これらすべてのクラスは `CFRuntimeClass` クラスのインスタンスです。`CFRuntimeClass` を呼び出すと、`__CFRuntimeClassTable` へのインデックスが返されます。CFRuntimeClass は [**CFRuntime.h**](https://opensource.apple.com/source/CF/CF-1153.18/CFRuntime.h.auto.html) で定義されています。
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

Objective-C runtime が使用するデータの大部分は実行中に変更されるため、メモリ上の Mach-O `__DATA` ファミリーのセグメントに含まれる複数のセクションを使用します。従来、これらには以下が含まれていました。

- `__objc_msgrefs` (`message_ref_t`): Message references
- `__objc_ivar` (`ivar`): Instance variables
- `__objc_data` (`...`): Mutable data
- `__objc_classrefs` (`Class`): Class references
- `__objc_superrefs` (`Class`): Superclass references
- `__objc_protorefs` (`protocol_t *`): Protocol references
- `__objc_selrefs` (`SEL`): Selector references
- `__objc_const` (`...`): Class r/o data およびその他の（期待される）constant data
- `__objc_imageinfo` (`version, flags`): image load 中に使用されます。現在の Version は `0` です。Flags は preoptimized GC support などを指定します
- `__objc_protolist` (`protocol_t *`): Protocol list
- `__objc_nlcatlist` (`category_t`): この binary で定義された Non-Lazy Categories への Pointer
- `__objc_catlist` (`category_t`): この binary で定義された Categories への Pointer
- `__objc_nlclslist` (`classref_t`): この binary で定義された Non-Lazy Objective-C classes への Pointer
- `__objc_classlist` (`classref_t`): この binary で定義されたすべての Objective-C classes への Pointer

また、constants を格納するために `__TEXT` セグメント内のいくつかのセクションも使用します。

- `__objc_methname` (C-String): Method names
- `__objc_classname` (C-String): Class names
- `__objc_methtype` (C-String): Method types

Modern macOS/iOS（特に Apple Silicon）では、Objective-C/Swift metadata も以下に配置されます。

- `__DATA_CONST`: read-only で process 間共有できる immutable Objective-C metadata（たとえば、多くの `__objc_*` lists が現在ここに配置されています）。
- `__AUTH` / `__AUTH_CONST`: arm64e で load 時または使用時に認証が必要な pointers（Pointer Authentication）を含むセグメント。legacy の `__la_symbol_ptr`/`__got` だけでなく、`__AUTH_CONST` 内の `__auth_got` も確認できます。modern binaries の instrumenting または hooking の際は、`__got` と `__auth_got` の両方の entries を考慮してください。

dyld pre-optimization（selector uniquing や class/protocol precomputation など）の背景、および shared cache 由来の場合にこれらの多くの sections が「すでに fixed up」されている理由については、Apple の `objc-opt` sources と dyld shared cache notes を確認してください。これは runtime で metadata を patch できる場所と方法に影響します。

{{#ref}}
../macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.md
{{#endref}}

### Type Encoding

Objective-C は、単純な type と複雑な type の selector および variable types を encode するために mangling を使用します。

- Primitive types は type の最初の letter を使用します。`int` には `i`、`char` には `c`、`long` には `l` などを使用し、unsigned の場合は capital letter を使用します（`unsigned long` には `L`）。
- その他の data types には、`long long` を表す `q`、bitfields を表す `b`、booleans を表す `B`、classes を表す `#`、`id` を表す `@`、`char *` を表す `*`、generic pointers を表す `^`、undefined を表す `?` など、その他の letters または symbols を使用します。
- Arrays、structures、unions には、それぞれ `[`, `{`、`(` を使用します。

#### Example Method Declaration
```objectivec
- (NSString *)processString:(id)input withOptions:(char *)options andError:(id)error;
```
selector は `processString:withOptions:andError:` になります。

#### Type Encoding

- `id` は `@` として encode されます
- `char *` は `*` として encode されます

この method の完全な type encoding は次のとおりです:
```less
@24@0:8@16*20^@24
```
#### 詳細な内訳

1. Return Type (`NSString *`): 長さ 24 の `@` としてエンコード
2. `self`（object instance）: `@` としてエンコード、offset 0
3. `_cmd`（selector）: `:` としてエンコード、offset 8
4. First argument（`char * input`）: `*` としてエンコード、offset 16
5. Second argument（`NSDictionary * options`）: `@` としてエンコード、offset 20
6. Third argument（`NSError ** error`）: `^@` としてエンコード、offset 24

selector と encoding を使用すると、method を再構築できます。

### Classes

Objective‑C の Classes は、properties、method pointers などを持つ C structs です。`objc_class` struct は[**source code**](https://opensource.apple.com/source/objc4/objc4-756.2/runtime/objc-runtime-new.h.auto.html)で確認できます。
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
このクラスは、`isa` フィールドの一部を使用してクラスに関する情報を示します。

さらに、この struct には、ディスク上に保存された `class_ro_t` struct へのポインタがあります。この struct には、クラス名、base methods、properties、instance variables などのクラス属性が含まれています。runtime では、methods、protocols、properties などの変更可能なポインタを含む追加の `class_rw_t` 構造体が使用されます。

{{#ref}}
../macos-basic-objective-c.md
{{#endref}}

---

## メモリ内の最新の object 表現（arm64e、tagged pointers、Swift）

### Non‑pointer `isa` と Pointer Authentication（arm64e）

Apple Silicon および最近の runtime では、Objective‑C の `isa` は必ずしも raw class pointer ではありません。arm64e では、Pointer Authentication Code（PAC）も保持できる packed structure です。platform によっては、`nonpointer`、`has_assoc`、`weakly_referenced`、`extra_rc`、および class pointer 自体（shift または signed 形式）などのフィールドを含む場合があります。つまり、Objective‑C object の先頭 8 bytes を無条件に dereference しても、常に有効な `Class` pointer が得られるとは限りません。<sup>[[2]](#references)</sup>

arm64e で debugging する際の実用的な注意事項：

- LLDB は通常、`po` で Objective‑C objects を表示する際に PAC bits を strip しますが、raw pointers を扱う場合は authentication を手動で strip する必要があります。

```lldb
(lldb) expr -l objc++ -- #include <ptrauth.h>
(lldb) expr -l objc++ -- void *raw = ptrauth_strip((void*)0x000000016f123abc, ptrauth_key_asda);
(lldb) expr -l objc++ -O -- (Class)object_getClass((id)raw)
```

- Mach‑O 内の多くの function/data pointers は `__AUTH`/`__AUTH_CONST` に存在し、使用前に authentication が必要です。interposing または re-binding（fishhook-style など）を行う場合は、legacy の `__got` に加えて `__auth_got` も処理するようにしてください。

language/ABI の guarantees と、Clang/LLVM で利用可能な `<ptrauth.h>` intrinsics の詳細については、このページの末尾にある reference を参照してください。<sup>[[1]](#references)</sup>

### Tagged pointer objects

一部の Foundation classes は、object の payload を pointer value に直接 encode する（tagged pointers）ことで、heap allocation を回避します。検出方法は platform によって異なります（例：arm64 では most-significant bit、x86_64 macOS では least-significant bit）。Tagged objects には、memory に保存された通常の `isa` がありません。runtime は tag bits から class を解決します。<sup>[[2]](#references)</sup> 任意の `id` values を inspecting する場合：

- `isa` field を直接調べるのではなく、runtime APIs を使用します：`object_getClass(obj)` / `[obj class]`。
- LLDB では、`po (id)0xADDR` を実行するだけで tagged pointer instances が正しく表示されます。これは runtime が class の解決に使用されるためです。

### Swift heap objects と metadata

Pure Swift classes も、Swift metadata を指す header を持つ objects です（Objective‑C の `isa` ではありません）。process を変更せずに live Swift processes を introspect するには、Swift toolchain の `swift-inspect` を使用できます。これは Remote Mirror library を利用して runtime metadata を読み取ります：
```bash
# Xcode toolchain (or Swift.org toolchain) provides swift-inspect
swift-inspect dump-raw-metadata <pid-or-name>
swift-inspect dump-arrays <pid-or-name>
# On Darwin additionally:
swift-inspect dump-concurrency <pid-or-name>
```
これは、Swift/ObjC 混在アプリを reverse engineering する際に、Swift heap objects と protocol conformances をマッピングするのに非常に役立ちます。

---

## Runtime inspection cheatsheet (LLDB / Frida)

### LLDB

- raw pointer から object または class を表示する：
```lldb
(lldb) expr -l objc++ -O -- (id)0x0000000101234560
(lldb) expr -l objc++ -O -- (Class)object_getClass((id)0x0000000101234560)
```
- breakpoint で、object method の `self` へのポインターから Objective-C class を調べる：
```lldb
(lldb) br se -n '-[NSFileManager fileExistsAtPath:]'
(lldb) r
... breakpoint hit ...
(lldb) po (id)$x0                 # self
(lldb) expr -l objc++ -O -- (Class)object_getClass((id)$x0)
```
- Objective-C metadataを保持するセクションをDumpする（注: 現在ではその多くが`__DATA_CONST` / `__AUTH_CONST`に存在します）：
```lldb
(lldb) image dump section --section __DATA_CONST.__objc_classlist
(lldb) image dump section --section __DATA_CONST.__objc_selrefs
(lldb) image dump section --section __AUTH_CONST.__auth_got
```
- 既知のクラスオブジェクトのメモリを読み取り、メソッドリストを reverse する際に `class_ro_t` / `class_rw_t` へ pivot する:
```lldb
(lldb) image lookup -r -n _OBJC_CLASS_$_NSFileManager
(lldb) memory read -fx -s8 0xADDRESS_OF_CLASS_OBJECT
```
### Frida（Objective-CおよびSwift）

Fridaは、シンボルなしで実行中のオブジェクトを発見・計測するのに非常に便利な、高レベルのruntime bridgeを提供します。

- classとmethodを列挙し、実行時に実際のclass名を解決し、Objective-Cのselectorをinterceptします:
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
- Swift bridge: Swiftの型を列挙し、Swiftのインスタンスとやり取りする（新しいバージョンのFridaが必要。Apple Silicon targetsで非常に有用）。

---

## 参考文献

- [1] [Clang/LLVM: Pointer Authenticationとptrauth.h intrinsics（arm64e ABI）](https://clang.llvm.org/docs/PointerAuthentication.html)
- [2] [Apple objc runtime headers - objc-object.h（tagged pointers、non-pointer isaなど）](https://opensource.apple.com/source/objc4/objc4-818.2/runtime/objc-object.h.auto.html)

{{#include ../../../banners/hacktricks-training.md}}
