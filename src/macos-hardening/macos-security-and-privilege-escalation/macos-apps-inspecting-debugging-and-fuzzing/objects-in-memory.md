# Objects in memory

{{#include ../../../banners/hacktricks-training.md}}

## CFRuntimeClass

CF* オブジェクトは CoreFoundation に由来し、`CFString`、`CFNumber`、`CFAllocator` のような 50 を超えるクラスのオブジェクトを提供します。

これらすべてのクラスは `CFRuntimeClass` クラスのインスタンスであり、呼び出されると `__CFRuntimeClassTable` へのインデックスを返します。`CFRuntimeClass` は [**CFRuntime.h**](https://opensource.apple.com/source/CF/CF-1153.18/CFRuntime.h.auto.html):
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

### 使用されるメモリセクション

Objective‑C runtime が実行中に使用するデータの大部分は変化するため、メモリ上の Mach‑O `__DATA` ファミリーのいくつかのセクションを使用します。歴史的にはこれらが含まれていました:

- `__objc_msgrefs` (`message_ref_t`): メッセージ参照
- `__objc_ivar` (`ivar`): インスタンス変数
- `__objc_data` (`...`): 変更可能なデータ
- `__objc_classrefs` (`Class`): クラス参照
- `__objc_superrefs` (`Class`): スーパークラス参照
- `__objc_protorefs` (`protocol_t *`): プロトコル参照
- `__objc_selrefs` (`SEL`): セレクタ参照
- `__objc_const` (`...`): クラスの読み取り専用データやその他（可能な限り）定数データ
- `__objc_imageinfo` (`version, flags`): イメージロード時に使用：現在の Version は `0`；Flags は事前最適化された GC サポート等を指定
- `__objc_protolist` (`protocol_t *`): プロトコルリスト
- `__objc_nlcatlist` (`category_t`): このバイナリ内で定義された Non-Lazy Categories へのポインタ
- `__objc_catlist` (`category_t`): このバイナリ内で定義された Categories へのポインタ
- `__objc_nlclslist` (`classref_t`): このバイナリ内で定義された Non-Lazy Objective‑C クラスへのポインタ
- `__objc_classlist` (`classref_t`): このバイナリ内で定義されたすべての Objective‑C クラスへのポインタ

定数を格納するために `__TEXT` セグメントのいくつかのセクションも使用します:

- `__objc_methname` (C‑String): メソッド名
- `__objc_classname` (C‑String): クラス名
- `__objc_methtype` (C‑String): メソッド型

Modern macOS/iOS（特に Apple Silicon）では Objective‑C/Swift メタデータを次にも配置します:

- `__DATA_CONST`: プロセス間で読み取り専用として共有可能な不変の Objective‑C メタデータ（例：多くの `__objc_*` リストがここに移動している）
- `__AUTH` / `__AUTH_CONST`: arm64e の Pointer Authentication によりロード時または使用時に認証される必要があるポインタを含むセグメント。従来の `__la_symbol_ptr`/`__got` の代わりに `__auth_got` が `__AUTH_CONST` 内に見られることもあります。インストルメンテーションやフックを行う際は、モダンなバイナリで `__got` と `__auth_got` の両方のエントリを考慮することを忘れないでください。

dyld の事前最適化（例えばセレクタのユニーク化やクラス/プロトコルの事前計算）と、これら多くのセクションが shared cache から来る際に「すでに固定済み」である理由の背景については、Apple の `objc-opt` ソースと dyld shared cache ノートを確認してください。これはランタイムでメタデータをパッチする場所と方法に影響します。

{{#ref}}
../macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.md
{{#endref}}

### Type Encoding

Objective‑C は簡単な型や複雑な型の selector や変数型をエンコードするためにマングリングを使用します:

- プリミティブ型は型名の最初の文字を使用します — `i` は `int`、`c` は `char`、`l` は `long` など。無符号の場合は大文字を使用します（`L` は `unsigned long`）。
- その他のデータ型は別の文字や記号を使用します。例：`q` は `long long`、`b` は bitfields、`B` は boolean、`#` は classes、`@` は `id`、`*` は `char *`、`^` は汎用ポインタ、`?` は未定義。
- 配列、構造体、共用体はそれぞれ `[`、`{`、`(` を使用します。

#### Example Method Declaration
```objectivec
- (NSString *)processString:(id)input withOptions:(char *)options andError:(id)error;
```
セレクタは `processString:withOptions:andError:` です

#### 型エンコーディング

- `id` は `@` としてエンコードされます
- `char *` は `*` としてエンコードされます

メソッドの完全な型エンコーディングは次のとおりです：
```less
@24@0:8@16*20^@24
```
#### 詳細な内訳

1. 戻り値の型 (`NSString *`): `@` としてエンコードされ、長さは 24
2. `self`（オブジェクトインスタンス）: `@` としてエンコード、オフセット 0
3. `_cmd`（セレクタ）: `:` としてエンコード、オフセット 8
4. 最初の引数 (`char * input`): `*` としてエンコード、オフセット 16
5. 2番目の引数 (`NSDictionary * options`): `@` としてエンコード、オフセット 20
6. 3番目の引数 (`NSError ** error`): `^@` としてエンコード、オフセット 24

セレクタとエンコーディングを組み合わせることでメソッドを再構築できます。

### クラス

Objective‑C のクラスはプロパティやメソッドポインタなどを持つ C の構造体です。struct `objc_class` は [**source code**](https://opensource.apple.com/source/objc4/objc4-756.2/runtime/objc-runtime-new.h.auto.html) で確認できます:
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
このクラスはクラスに関する情報を示すために `isa` フィールドのいくつかのビットを使用します。

また、struct はディスク上に格納された `class_ro_t` 構造体へのポインタを持ち、そこにはクラス名、基本メソッド、プロパティ、インスタンス変数などの属性が含まれます。ランタイム時には、メソッド、プロトコル、プロパティなど変更可能なポインタを含む追加の構造体 `class_rw_t` が使用されます。

{{#ref}}
../macos-basic-objective-c.md
{{#endref}}

---

## メモリ内の現代的なオブジェクト表現 (arm64e、tagged pointers、Swift)

### 非ポインタ `isa` と Pointer Authentication (arm64e)

Apple Silicon と最近のランタイムでは、Objective‑C の `isa` が常に生のクラスポインタとは限りません。arm64e では `isa` はパックされた構造体であり、Pointer Authentication Code (PAC) を含む場合があります。プラットフォームによっては `nonpointer`、`has_assoc`、`weakly_referenced`、`extra_rc`、および（シフトまたは符号化された）クラスポインタ自体のようなフィールドを含むことがあります。つまり、Objective‑C オブジェクトの先頭 8 バイトを盲目的にデリファレンスしても有効な `Class` ポインタが得られるとは限りません。

arm64e でデバッグする際の実務的な注意点：

- LLDB は通常 `po` で Objective‑C オブジェクトを表示する際に PAC ビットを取り除いてくれますが、生のポインタを扱うときは認証を手動で剥がす必要がある場合があります:

```lldb
(lldb) expr -l objc++ -- #include <ptrauth.h>
(lldb) expr -l objc++ -- void *raw = ptrauth_strip((void*)0x000000016f123abc, ptrauth_key_asda);
(lldb) expr -l objc++ -O -- (Class)object_getClass((id)raw)
```

- Mach‑O 内の多くの関数/データポインタは `__AUTH`/`__AUTH_CONST` に存在し、使用前に認証が必要です。インターポーズや再バインド（例: fishhook スタイル）を行う場合は、レガシーな `__got` に加えて `__auth_got` の処理も行ってください。

言語/ABI の保証や Clang/LLVM で利用可能な `<ptrauth.h>` のイントリンシックの詳細については、このページの末尾の参照を参照してください。

### タグ付きポインタオブジェクト

一部の Foundation クラスはオブジェクトのペイロードをポインタ値に直接エンコードする（tagged pointers）ことでヒープ割り当てを回避します。検出方法はプラットフォームによって異なります（例: arm64 では最上位ビット、x86_64 macOS では最下位ビット）。タグ付きオブジェクトはメモリに通常の `isa` を持たず、ランタイムがタグビットからクラスを解決します。任意の `id` 値を調べるときは：

- `isa` フィールドを直接覗くのではなく、ランタイム API を使用してください: `object_getClass(obj)` / `[obj class]`。
- LLDB では `po (id)0xADDR` とするだけで、ランタイムがクラス解決に相談されるためタグ付きポインタのインスタンスを正しく表示します。

### Swift ヒープオブジェクトとメタデータ

純粋な Swift クラスもヘッダが Swift メタデータ（Objective‑C の `isa` ではない）を指すオブジェクトです。変更せずに稼働中の Swift プロセスを調査するには、Swift ツールチェーンの `swift-inspect` を使用できます。これは Remote Mirror ライブラリを利用してランタイムメタデータを読み取ります:
```bash
# Xcode toolchain (or Swift.org toolchain) provides swift-inspect
swift-inspect dump-raw-metadata <pid-or-name>
swift-inspect dump-arrays <pid-or-name>
# On Darwin additionally:
swift-inspect dump-concurrency <pid-or-name>
```
これは、Swift/ObjCが混在するアプリをリバースエンジニアリングする際に、Swiftのヒープオブジェクトやプロトコル適合をマッピングするのに非常に役立ちます。

---

## Runtime inspection cheatsheet (LLDB / Frida)

### LLDB

- Print object or class from a raw pointer:
```lldb
(lldb) expr -l objc++ -O -- (id)0x0000000101234560
(lldb) expr -l objc++ -O -- (Class)object_getClass((id)0x0000000101234560)
```
- breakpoint内でオブジェクトメソッドの`self`へのpointerからObjective‑C classを調査する:
```lldb
(lldb) br se -n '-[NSFileManager fileExistsAtPath:]'
(lldb) r
... breakpoint hit ...
(lldb) po (id)$x0                 # self
(lldb) expr -l objc++ -O -- (Class)object_getClass((id)$x0)
```
- Objective‑C メタデータを含むセクションをダンプする（注：多くは現在 `__DATA_CONST` / `__AUTH_CONST` にあります）:
```lldb
(lldb) image dump section --section __DATA_CONST.__objc_classlist
(lldb) image dump section --section __DATA_CONST.__objc_selrefs
(lldb) image dump section --section __AUTH_CONST.__auth_got
```
- 既知のクラスオブジェクトのメモリを読み、メソッドリストを逆解析する際に `class_ro_t` / `class_rw_t` にピボットする:
```lldb
(lldb) image lookup -r -n _OBJC_CLASS_$_NSFileManager
(lldb) memory read -fx -s8 0xADDRESS_OF_CLASS_OBJECT
```
### Frida (Objective‑C and Swift)

Frida はシンボルなしでライブオブジェクトを発見・操作するための高レベルなランタイムブリッジを提供します:

- クラスやメソッドを列挙し、実行時に実際のクラス名を解決し、Objective‑C selectors をインターセプトします:
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
- Swift bridge: Swift 型を列挙し、Swift インスタンスとやり取りする（最新の Frida が必要; Apple Silicon ターゲットで非常に有用）。

---

## 参考資料

- Clang/LLVM: Pointer Authentication と `<ptrauth.h>` の intrinsics (arm64e ABI). https://clang.llvm.org/docs/PointerAuthentication.html
- Apple objc runtime ヘッダ（tagged pointers、non‑pointer `isa` など）。例: `objc-object.h`. https://opensource.apple.com/source/objc4/objc4-818.2/runtime/objc-object.h.auto.html

{{#include ../../../banners/hacktricks-training.md}}
