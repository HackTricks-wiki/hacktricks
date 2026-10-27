# Objects trong bộ nhớ

{{#include ../../../banners/hacktricks-training.md}}

## CFRuntimeClass

Các object CF* đến từ CoreFoundation, cung cấp hơn 50 class object như `CFString`, `CFNumber` hoặc `CFAllocator`.

Tất cả các class này đều là instance của class `CFRuntimeClass`. Khi được gọi, class này trả về một chỉ mục trỏ đến `__CFRuntimeClassTable`. CFRuntimeClass được định nghĩa trong [**CFRuntime.h**](https://opensource.apple.com/source/CF/CF-1153.18/CFRuntime.h.auto.html):

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

### Các section bộ nhớ được sử dụng

Phần lớn dữ liệu được Objective‑C runtime sử dụng sẽ thay đổi trong quá trình thực thi, vì vậy runtime dùng một số section thuộc họ segment Mach‑O `__DATA` trong bộ nhớ. Trước đây, các section này bao gồm:

- `__objc_msgrefs` (`message_ref_t`): Các tham chiếu message
- `__objc_ivar` (`ivar`): Các biến instance
- `__objc_data` (`...`): Dữ liệu có thể thay đổi
- `__objc_classrefs` (`Class`): Các tham chiếu lớp
- `__objc_superrefs` (`Class`): Các tham chiếu lớp cha
- `__objc_protorefs` (`protocol_t *`): Các tham chiếu protocol
- `__objc_selrefs` (`SEL`): Các tham chiếu selector
- `__objc_const` (`...`): Dữ liệu chỉ đọc của lớp và dữ liệu khác được cho là hằng số
- `__objc_imageinfo` (`version, flags`): Được dùng khi nạp image: Phiên bản hiện tại là `0`; Flags chỉ định hỗ trợ GC được tiền tối ưu hóa, v.v.
- `__objc_protolist` (`protocol_t *`): Danh sách protocol
- `__objc_nlcatlist` (`category_t`): Con trỏ đến các Category Non-Lazy được định nghĩa trong binary này
- `__objc_catlist` (`category_t`): Con trỏ đến các Category được định nghĩa trong binary này
- `__objc_nlclslist` (`classref_t`): Con trỏ đến các lớp Objective‑C Non-Lazy được định nghĩa trong binary này
- `__objc_classlist` (`classref_t`): Con trỏ đến tất cả các lớp Objective‑C được định nghĩa trong binary này

Runtime cũng dùng một vài section trong segment `__TEXT` để lưu các hằng số:

- `__objc_methname` (C‑String): Tên method
- `__objc_classname` (C‑String): Tên lớp
- `__objc_methtype` (C‑String): Kiểu method

Các phiên bản macOS/iOS hiện đại (đặc biệt trên Apple Silicon) cũng đặt metadata Objective‑C/Swift trong:

- `__DATA_CONST`: Metadata Objective‑C bất biến, có thể được chia sẻ chỉ đọc giữa các tiến trình (ví dụ, nhiều danh sách `__objc_*` hiện nằm ở đây).
- `__AUTH` / `__AUTH_CONST`: Các segment chứa con trỏ cần được xác thực khi nạp hoặc sử dụng trên arm64e (Pointer Authentication). Bạn cũng sẽ thấy `__auth_got` trong `__AUTH_CONST`, thay vì chỉ có `__la_symbol_ptr`/`__got` như trước đây. Khi instrument hoặc hooking, hãy nhớ tính đến cả các entry `__got` lẫn `__auth_got` trong các binary hiện đại.

Để tìm hiểu về dyld pre-optimization (ví dụ: selector uniquing và tiền tính toán class/protocol), cũng như lý do nhiều section trong số này “đã được fix up” khi lấy từ shared cache, hãy xem mã nguồn `objc-opt` của Apple và ghi chú về dyld shared cache. Điều này ảnh hưởng đến vị trí và cách bạn có thể patch metadata lúc runtime.

{{#ref}}
../macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.md
{{#endref}}

### Mã hóa kiểu

Objective‑C dùng mangling để mã hóa kiểu của selector và biến, bao gồm các kiểu đơn giản và phức tạp:

- Kiểu nguyên thủy dùng chữ cái đầu tiên của tên kiểu: `i` cho `int`, `c` cho `char`, `l` cho `long`... và dùng chữ hoa nếu là kiểu không dấu (`L` cho `unsigned long`).
- Các kiểu dữ liệu khác dùng những chữ cái hoặc ký hiệu khác, chẳng hạn `q` cho `long long`, `b` cho bitfield, `B` cho boolean, `#` cho class, `@` cho `id`, `*` cho `char *`, `^` cho con trỏ tổng quát và `?` cho kiểu không xác định.
- Mảng, cấu trúc và union lần lượt dùng `[`, `{` và `(`.

#### Ví dụ khai báo Method

```objectivec
- (NSString *)processString:(id)input withOptions:(char *)options andError:(id)error;
```

Selector sẽ là `processString:withOptions:andError:`

#### Chữ ký được mã hóa

- `id` được mã hóa thành `@`
- `char *` được mã hóa thành `*`

Mã hóa kiểu đầy đủ của phương thức là:

```less
@24@0:8@16*20^@24
```

#### Phân tích chi tiết

1. Kiểu trả về (`NSString *`): Được mã hóa là `@` với độ dài 24
2. `self` (instance của object): Được mã hóa là `@`, tại offset 0
3. `_cmd` (selector): Được mã hóa là `:`, tại offset 8
4. Đối số thứ nhất (`char * input`): Được mã hóa là `*`, tại offset 16
5. Đối số thứ hai (`NSDictionary * options`): Được mã hóa là `@`, tại offset 20
6. Đối số thứ ba (`NSError ** error`): Được mã hóa là `^@`, tại offset 24

Với selector và encoding, bạn có thể tái dựng method.

### Các lớp

Các lớp trong Objective-C là những struct C có thuộc tính, con trỏ method, v.v. Có thể tìm thấy struct `objc_class` trong [**source code**](https://opensource.apple.com/source/objc4/objc4-756.2/runtime/objc-runtime-new.h.auto.html):

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

Class này sử dụng một số bit trong trường `isa` để biểu thị thông tin về class.

Sau đó, struct này có một con trỏ tới struct `class_ro_t` được lưu trên đĩa, chứa các thuộc tính của class như tên, các phương thức cơ sở, properties và biến instance. Trong runtime, một cấu trúc bổ sung `class_rw_t` được sử dụng, chứa các con trỏ có thể được thay đổi, chẳng hạn như phương thức, protocol và property.

{{#ref}}
../macos-basic-objective-c.md
{{#endref}}

---

## Các biểu diễn object hiện đại trong bộ nhớ (arm64e, tagged pointer, Swift)

### `isa` không phải con trỏ và Pointer Authentication (arm64e)

Trên Apple Silicon và các runtime gần đây, `isa` của Objective‑C không phải lúc nào cũng là con trỏ class thô. Trên arm64e, đây là một cấu trúc đóng gói, cũng có thể chứa Pointer Authentication Code (PAC). Tùy nền tảng, nó có thể bao gồm các trường như `nonpointer`, `has_assoc`, `weakly_referenced`, `extra_rc` và chính con trỏ class (được dịch bit hoặc ký). Điều này có nghĩa là việc dereference mù quáng 8 byte đầu tiên của một object Objective‑C không phải lúc nào cũng trả về một con trỏ `Class` hợp lệ.<sup>[[2]](#references)</sup>

Ghi chú thực tế khi debug trên arm64e:

- LLDB thường sẽ loại bỏ các bit PAC giúp bạn khi in các object Objective‑C bằng `po`, nhưng khi làm việc với con trỏ thô, bạn có thể cần tự loại bỏ phần xác thực:
  
  ```lldb
  (lldb) expr -l objc++ -- #include <ptrauth.h>
  (lldb) expr -l objc++ -- void *raw = ptrauth_strip((void*)0x000000016f123abc, ptrauth_key_asda);
  (lldb) expr -l objc++ -O -- (Class)object_getClass((id)raw)
  ```

- Nhiều con trỏ hàm/dữ liệu trong Mach‑O nằm trong `__AUTH`/`__AUTH_CONST` và cần được xác thực trước khi sử dụng. Nếu bạn đang interpose hoặc re-bind (ví dụ theo kiểu fishhook), hãy đảm bảo xử lý cả `__auth_got` bên cạnh `__got` kiểu cũ.

Để tìm hiểu sâu về các bảo đảm của ngôn ngữ/ABI và các intrinsic trong `<ptrauth.h>` có sẵn từ Clang/LLVM, xem tài liệu tham khảo ở cuối trang này.<sup>[[1]](#references)</sup>

### Các object tagged pointer

Một số lớp Foundation tránh cấp phát trên heap bằng cách mã hóa trực tiếp payload của object vào giá trị con trỏ (tagged pointer). Cách phát hiện khác nhau tùy nền tảng (ví dụ: bit có trọng số cao nhất trên arm64, bit có trọng số thấp nhất trên macOS x86_64). Các object tagged pointer không có `isa` thông thường được lưu trong bộ nhớ; runtime xác định lớp từ các bit tag.<sup>[[2]](#references)</sup> Khi kiểm tra các giá trị `id` bất kỳ:

- Dùng API runtime thay vì truy cập trực tiếp trường `isa`: `object_getClass(obj)` / `[obj class]`.
- Trong LLDB, chỉ cần dùng `po (id)0xADDR` để in các instance tagged pointer chính xác, vì runtime được tham vấn để xác định lớp.

### Object heap Swift và metadata

Các lớp thuần Swift cũng là object có header trỏ đến metadata Swift (không phải `isa` Objective‑C). Để xem xét các tiến trình Swift đang chạy mà không sửa đổi chúng, bạn có thể dùng `swift-inspect` trong Swift toolchain; công cụ này tận dụng thư viện Remote Mirror để đọc metadata runtime:

```bash
# Xcode toolchain (or Swift.org toolchain) provides swift-inspect
swift-inspect dump-raw-metadata <pid-or-name>
swift-inspect dump-arrays <pid-or-name>
# On Darwin additionally:
swift-inspect dump-concurrency <pid-or-name>
```

Điều này rất hữu ích để lập bản đồ các đối tượng trên heap của Swift và các kiểu tuân thủ protocol khi reverse các ứng dụng kết hợp Swift/ObjC.

---

## Bảng tham khảo nhanh về kiểm tra runtime (LLDB / Frida)

### LLDB

- In đối tượng hoặc class từ một con trỏ thô:

```lldb
(lldb) expr -l objc++ -O -- (id)0x0000000101234560
(lldb) expr -l objc++ -O -- (Class)object_getClass((id)0x0000000101234560)
```

- Kiểm tra lớp Objective-C thông qua con trỏ tới `self` của một phương thức đối tượng tại breakpoint:

```lldb
(lldb) br se -n '-[NSFileManager fileExistsAtPath:]'
(lldb) r
... breakpoint hit ...
(lldb) po (id)$x0                 # self
(lldb) expr -l objc++ -O -- (Class)object_getClass((id)$x0)
```

- Dump các section chứa metadata Objective-C (lưu ý: hiện nay nhiều section nằm trong `__DATA_CONST` / `__AUTH_CONST`):

```lldb
(lldb) image dump section --section __DATA_CONST.__objc_classlist
(lldb) image dump section --section __DATA_CONST.__objc_selrefs
(lldb) image dump section --section __AUTH_CONST.__auth_got
```

- Đọc bộ nhớ của một đối tượng class đã biết để chuyển sang `class_ro_t` / `class_rw_t` khi phân tích ngược các danh sách method:

```lldb
(lldb) image lookup -r -n _OBJC_CLASS_$_NSFileManager
(lldb) memory read -fx -s8 0xADDRESS_OF_CLASS_OBJECT
```

### Frida (Objective‑C và Swift)

Frida cung cấp các cầu nối runtime cấp cao, rất hữu ích để phát hiện và instrument các object đang hoạt động mà không cần symbols:

- Liệt kê các class và method, phân giải tên class thực tế khi runtime, và chặn các Objective‑C selector:

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

- Swift bridge: liệt kê các kiểu Swift và tương tác với các instance Swift (yêu cầu Frida phiên bản mới; rất hữu ích trên các mục tiêu Apple Silicon).

---

## References


- [1] [Clang/LLVM: Xác thực con trỏ và các intrinsic của ptrauth.h (arm64e ABI)](https://clang.llvm.org/docs/PointerAuthentication.html)
- [2] [Mã nguồn mở của Apple - `objc-object.h` của Objective-C runtime](https://github.com/apple-oss-distributions/objc4/blob/main/runtime/objc-object.h)
{{#include ../../../banners/hacktricks-training.md}}
