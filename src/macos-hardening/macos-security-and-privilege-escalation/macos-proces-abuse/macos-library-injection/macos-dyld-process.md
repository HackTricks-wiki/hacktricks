# Quy trình Dyld trên macOS

{{#include ../../../../banners/hacktricks-training.md}}

## Thông tin cơ bản

**Entrypoint** thực sự của một binary Mach-o là dynamic linker, được chỉ định trong `LC_LOAD_DYLINKER`, thường là `/usr/lib/dyld`.<sup>[[3]](#references)</sup>

Linker này cần tìm tất cả các thư viện của executable, ánh xạ chúng vào bộ nhớ và liên kết tất cả các thư viện non-lazy. Chỉ sau quá trình này, entry point của binary mới được thực thi.

Tất nhiên, **`dyld`** không có dependency nào (nó sử dụng syscall và các đoạn trích từ libSystem).

> [!CAUTION]
> Nếu linker này có lỗ hổng, vì nó được thực thi trước bất kỳ binary nào (kể cả các binary có đặc quyền cao), thì có thể **escalate privileges**.

### Luồng

Dyld được tải bởi **`dyldboostrap::start`**, hàm này cũng tải những thứ như **stack canary**. Đó là vì hàm này nhận các **giá trị nhạy cảm** này và những giá trị khác trong vector argument **`apple`**.<sup>[[1]](#references)</sup>

**`dyls::_main()`** là entry point của dyld và nhiệm vụ đầu tiên của nó là chạy `configureProcessRestrictions()`, hàm này thường hạn chế các biến môi trường **`DYLD_*`** được giải thích trong:<sup>[[2]](#references)</sup>


{{#ref}}
./
{{#endref}}

Sau đó, nó ánh xạ dyld shared cache, nơi đã prelink tất cả các thư viện hệ thống quan trọng, rồi ánh xạ các thư viện mà binary phụ thuộc vào và tiếp tục đệ quy cho đến khi tất cả thư viện cần thiết được tải. Do đó:

1. Nó bắt đầu tải các thư viện được chèn bằng `DYLD_INSERT_LIBRARIES` (nếu được cho phép)
2. Sau đó là các thư viện trong shared cache
3. Tiếp theo là các thư viện được import
   1. Sau đó tiếp tục import thư viện theo cách đệ quy

Khi tất cả đã được tải, các **initialiser** của những thư viện này sẽ chạy. Chúng được viết bằng **`__attribute__((constructor))`**, định nghĩa trong `LC_ROUTINES[_64]` (hiện đã deprecated) hoặc bằng pointer trong section có cờ `S_MOD_INIT_FUNC_POINTERS` (thường là: **`__DATA.__MOD_INIT_FUNC`**).

Terminator được viết bằng **`__attribute__((destructor))`** và nằm trong section có cờ `S_MOD_TERM_FUNC_POINTERS` (**`__DATA.__mod_term_func`**).

Xem thêm: [Reflective Mach-O Loading](../reflective-mach-o-loading.md).

### Stubs

Tất cả binary trên macOS đều được liên kết động. Do đó, chúng chứa một số section stub giúp binary nhảy đến đúng code trên các máy và trong những ngữ cảnh khác nhau. Khi binary được thực thi, dyld là thành phần cần phân giải các địa chỉ này (ít nhất là các địa chỉ non-lazy).

Một số section stub trong binary:

- **`__TEXT.__[auth_]stubs`**: Pointer từ các section `__DATA`
- **`__TEXT.__stub_helper`**: Đoạn code ngắn gọi dynamic linking kèm thông tin về function cần gọi
- **`__DATA.__[auth_]got`**: Global Offset Table (địa chỉ của các function được import; sau khi phân giải, chúng được bind lúc load time vì được đánh dấu bằng flag `S_NON_LAZY_SYMBOL_POINTERS`)
- **`__DATA.__nl_symbol_ptr`**: Pointer đến symbol non-lazy (được bind lúc load time vì được đánh dấu bằng flag `S_NON_LAZY_SYMBOL_POINTERS`)
- **`__DATA.__la_symbol_ptr`**: Pointer đến symbol lazy (được bind khi truy cập lần đầu)

> [!WARNING]
> Lưu ý rằng các pointer có tiền tố "auth\_" sử dụng một encryption key trong cùng process để bảo vệ chúng (PAC). Ngoài ra, có thể dùng instruction `BLRA[A/B]` của arm64 để xác minh pointer trước khi theo nó. Có thể dùng RETA\[A/B] thay cho địa chỉ RET.\
> Trên thực tế, code trong **`__TEXT.__auth_stubs`** sẽ dùng **`braa`** thay vì **`bl`** để gọi function được yêu cầu và xác thực pointer.
>
> Cũng lưu ý rằng các phiên bản dyld hiện tại tải **mọi thứ dưới dạng non-lazy**.

### Tìm lazy symbols

```c
//gcc load.c -o load
#include <stdio.h>
int main (int argc, char **argv, char **envp, char **apple)
{
    printf("Hi\n");
}
```

Phần disassembly đáng chú ý:

```armasm
; objdump -d ./load
100003f7c: 90000000    	adrp	x0, 0x100003000 <_main+0x1c>
100003f80: 913e9000    	add	x0, x0, #4004
100003f84: 94000005    	bl	0x100003f98 <_printf+0x100003f98>
```

Có thể thấy rằng lệnh nhảy để gọi `printf` sẽ đi tới **`__TEXT.__stubs`**:

```bash
objdump --section-headers ./load

./load:	file format mach-o arm64

Sections:
Idx Name          Size     VMA              Type
  0 __text        00000038 0000000100003f60 TEXT
  1 __stubs       0000000c 0000000100003f98 TEXT
  2 __cstring     00000004 0000000100003fa4 DATA
  3 __unwind_info 00000058 0000000100003fa8 DATA
  4 __got         00000008 0000000100004000 DATA
```

Trong kết quả disassemble của section **`__stubs`**:

```bash
objdump -d --section=__stubs ./load

./load:	file format mach-o arm64

Disassembly of section __TEXT,__stubs:

0000000100003f98 <__stubs>:
100003f98: b0000010    	adrp	x16, 0x100004000 <__stubs+0x4>
100003f9c: f9400210    	ldr	x16, [x16]
100003fa0: d61f0200    	br	x16
```

có thể thấy rằng chúng ta đang **nhảy đến địa chỉ của GOT**. Trong trường hợp này, địa chỉ đó được phân giải theo kiểu non-lazy và sẽ chứa địa chỉ của hàm printf.

Trong các trường hợp khác, thay vì nhảy trực tiếp đến GOT, chương trình có thể nhảy đến **`__DATA.__la_symbol_ptr`**. Mục này sẽ tải một giá trị đại diện cho hàm mà chương trình đang cố tải, sau đó nhảy đến **`__TEXT.__stub_helper`**. Mục này sẽ nhảy đến **`__DATA.__nl_symbol_ptr`**, nơi chứa địa chỉ của **`dyld_stub_binder`**. Hàm này nhận số hiệu của hàm và một địa chỉ làm tham số.\
Binder phân giải symbol và cập nhật slot **`__DATA.__la_symbol_ptr`** tương ứng. Trong các lần gọi sau, stub sử dụng con trỏ đã được phân giải đó; nó không được ghi đè trong **`__TEXT.__stub_helper`**.<sup>[[5]](#references)</sup>

> [!TIP]
> Tuy nhiên, hãy lưu ý rằng các phiên bản dyld hiện tại tải mọi thứ theo kiểu non-lazy.

#### Dyld opcodes

Cuối cùng, **`dyld_stub_binder`** cần tìm hàm được chỉ định và ghi địa chỉ của hàm đó vào đúng vị trí để không phải tìm lại. Để làm việc này, nó sử dụng opcodes (một máy trạng thái hữu hạn) bên trong dyld.

## apple\[] argument vector

Trong macOS, hàm main thực tế nhận 4 đối số thay vì 3. Đối số thứ tư được gọi là apple, và mỗi mục có dạng `key=value`. Ví dụ:

```c
// gcc apple.c -o apple
#include <stdio.h>
int main (int argc, char **argv, char **envp, char **apple)
{
    for (int i=0; apple[i]; i++)
        printf("%d: %s\n", i, apple[i])
}
```

Kết quả:

```
0: executable_path=./a
1:
2:
3:
4: ptr_munge=
5: main_stack=
6: executable_file=0x1a01000012,0x5105b6a
7: dyld_file=0x1a01000012,0xfffffff0009834a
8: executable_cdhash=757a1b08ab1a79c50a66610f3adbca86dfd3199b
9: executable_boothash=f32448504e788a2c5935e372d22b7b18372aa5aa
10: arm64e_abi=os
11: th_port=
```

> [!TIP]
> Khi các giá trị này đến được hàm main, thông tin nhạy cảm đã bị loại bỏ khỏi chúng; nếu không, đó sẽ là một vụ rò rỉ dữ liệu.

Có thể xem tất cả các giá trị thú vị này bằng cách debug trước khi vào main:

<pre><code>lldb ./apple

<strong>(lldb) target create "./a"
</strong>Current executable set to '/tmp/a' (arm64).
(lldb) process launch -s
[..]

<strong>(lldb) mem read $sp
</strong>0x16fdff510: 00 00 00 00 01 00 00 00 01 00 00 00 00 00 00 00  ................
0x16fdff520: d8 f6 df 6f 01 00 00 00 00 00 00 00 00 00 00 00  ...o............

<strong>(lldb) x/55s 0x016fdff6d8
</strong>[...]
0x16fdffd6a: "TERM_PROGRAM=WarpTerminal"
0x16fdffd84: "WARP_USE_SSH_WRAPPER=1"
0x16fdffd9b: "WARP_IS_LOCAL_SHELL_SESSION=1"
0x16fdffdb9: "SDKROOT=/Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX14.4.sdk"
0x16fdffe24: "NVM_DIR=/Users/carlospolop/.nvm"
0x16fdffe44: "CONDA_CHANGEPS1=false"
0x16fdffe5a: ""
0x16fdffe5b: ""
0x16fdffe5c: ""
0x16fdffe5d: ""
0x16fdffe5e: ""
0x16fdffe5f: ""
0x16fdffe60: "pfz=0xffeaf0000"
0x16fdffe70: "stack_guard=0x8af2b510e6b800b5"
0x16fdffe8f: "malloc_entropy=0xf2349fbdea53f1e4,0x3fd85d7dcf817101"
0x16fdffec4: "ptr_munge=0x983e2eebd2f3e746"
0x16fdffee1: "main_stack=0x16fe00000,0x7fc000,0x16be00000,0x4000000"
0x16fdfff17: "executable_file=0x1a01000012,0x5105b6a"
0x16fdfff3e: "dyld_file=0x1a01000012,0xfffffff0009834a"
0x16fdfff67: "executable_cdhash=757a1b08ab1a79c50a66610f3adbca86dfd3199b"
0x16fdfffa2: "executable_boothash=f32448504e788a2c5935e372d22b7b18372aa5aa"
0x16fdfffdf: "arm64e_abi=os"
0x16fdfffed: "th_port=0x103"
0x16fdffffb: ""
</code></pre>

## dyld_all_image_infos

Đây là cấu trúc được dyld xuất ra, chứa thông tin về trạng thái của dyld. Có thể tìm thấy cấu trúc này trong [**mã nguồn**](https://opensource.apple.com/source/dyld/dyld-852.2/include/mach-o/dyld_images.h.auto.html), với các thông tin như phiên bản, con trỏ đến mảng dyld_image_info, đến dyld_image_notifier, liệu proc có bị tách khỏi shared cache hay không, liệu bộ khởi tạo của libSystem đã được gọi hay chưa, con trỏ đến Mach header của chính dyld, con trỏ đến chuỗi phiên bản dyld...<sup>[[4]](#references)</sup>

## dyld env variables

### debug dyld

Các biến môi trường thú vị giúp tìm hiểu dyld đang làm gì:

- **DYLD_PRINT_LIBRARIES**

Kiểm tra từng library được tải:

```
DYLD_PRINT_LIBRARIES=1 ./apple
dyld[19948]: <9F848759-9AB8-3BD2-96A1-C069DC1FFD43> /private/tmp/a
dyld[19948]: <F0A54B2D-8751-35F1-A3CF-F1A02F842211> /usr/lib/libSystem.B.dylib
dyld[19948]: <C683623C-1FF6-3133-9E28-28672FDBA4D3> /usr/lib/system/libcache.dylib
dyld[19948]: <BFDF8F55-D3DC-3A92-B8A1-8EF165A56F1B> /usr/lib/system/libcommonCrypto.dylib
dyld[19948]: <B29A99B2-7ADE-3371-A774-B690BEC3C406> /usr/lib/system/libcompiler_rt.dylib
dyld[19948]: <65612C42-C5E4-3821-B71D-DDE620FB014C> /usr/lib/system/libcopyfile.dylib
dyld[19948]: <B3AC12C0-8ED6-35A2-86C6-0BFA55BFF333> /usr/lib/system/libcorecrypto.dylib
dyld[19948]: <8790BA20-19EC-3A36-8975-E34382D9747C> /usr/lib/system/libdispatch.dylib
dyld[19948]: <4BB77515-DBA8-3EDF-9AF7-3C9EAE959EA6> /usr/lib/system/libdyld.dylib
dyld[19948]: <F7CE9486-FFF5-3CB8-B26F-75811EF4283A> /usr/lib/system/libkeymgr.dylib
dyld[19948]: <1A7038EC-EE49-35AE-8A3C-C311083795FB> /usr/lib/system/libmacho.dylib
[...]
```

- **DYLD_PRINT_SEGMENTS**

Kiểm tra cách mỗi thư viện được tải:

```
DYLD_PRINT_SEGMENTS=1 ./apple
dyld[21147]: re-using existing shared cache (/System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e):
dyld[21147]:         0x181944000->0x1D5D4BFFF init=5, max=5 __TEXT
dyld[21147]:         0x1D5D4C000->0x1D5EC3FFF init=1, max=3 __DATA_CONST
dyld[21147]:         0x1D7EC4000->0x1D8E23FFF init=3, max=3 __DATA
dyld[21147]:         0x1D8E24000->0x1DCEBFFFF init=3, max=3 __AUTH
dyld[21147]:         0x1DCEC0000->0x1E22BFFFF init=1, max=3 __AUTH_CONST
dyld[21147]:         0x1E42C0000->0x1E5457FFF init=1, max=1 __LINKEDIT
dyld[21147]:         0x1E5458000->0x22D173FFF init=5, max=5 __TEXT
dyld[21147]:         0x22D174000->0x22D9E3FFF init=1, max=3 __DATA_CONST
dyld[21147]:         0x22F9E4000->0x230F87FFF init=3, max=3 __DATA
dyld[21147]:         0x230F88000->0x234EC3FFF init=3, max=3 __AUTH
dyld[21147]:         0x234EC4000->0x237573FFF init=1, max=3 __AUTH_CONST
dyld[21147]:         0x239574000->0x270BE3FFF init=1, max=1 __LINKEDIT
dyld[21147]: Kernel mapped /private/tmp/a
dyld[21147]:     __PAGEZERO (...) 0x000000904000->0x000101208000
dyld[21147]:         __TEXT (r.x) 0x000100904000->0x000100908000
dyld[21147]:   __DATA_CONST (rw.) 0x000100908000->0x00010090C000
dyld[21147]:     __LINKEDIT (r..) 0x00010090C000->0x000100910000
dyld[21147]: Using mapping in dyld cache for /usr/lib/libSystem.B.dylib
dyld[21147]:         __TEXT (r.x) 0x00018E59D000->0x00018E59F000
dyld[21147]:   __DATA_CONST (rw.) 0x0001D5DFDB98->0x0001D5DFDBA8
dyld[21147]:   __AUTH_CONST (rw.) 0x0001DDE015A8->0x0001DDE01878
dyld[21147]:         __AUTH (rw.) 0x0001D9688650->0x0001D9688658
dyld[21147]:         __DATA (rw.) 0x0001D808AD60->0x0001D808AD68
dyld[21147]:     __LINKEDIT (r..) 0x000239574000->0x000270BE4000
dyld[21147]: Using mapping in dyld cache for /usr/lib/system/libcache.dylib
dyld[21147]:         __TEXT (r.x) 0x00018E597000->0x00018E59D000
dyld[21147]:   __DATA_CONST (rw.) 0x0001D5DFDAF0->0x0001D5DFDB98
dyld[21147]:   __AUTH_CONST (rw.) 0x0001DDE014D0->0x0001DDE015A8
dyld[21147]:     __LINKEDIT (r..) 0x000239574000->0x000270BE4000
[...]
```

- **DYLD_PRINT_INITIALIZERS**

In ra khi trình khởi tạo của mỗi thư viện đang chạy:

```
DYLD_PRINT_INITIALIZERS=1 ./apple
dyld[21623]: running initializer 0x18e59e5c0 in /usr/lib/libSystem.B.dylib
[...]
```

### Theo dõi quá trình phân giải thư viện lúc runtime

Với một tiến trình khởi chạy mà bạn có thể kiểm soát, hãy theo dõi ứng viên `@rpath` hoặc weak-library trước khi đặt dylib thay thế. `DYLD_PRINT_SEARCHING` báo cáo các đường dẫn mà dyld xem xét, còn `DYLD_PRINT_LIBRARIES` hiển thị các image thực sự được tải. `DYLD_PRINT_LOADERS` phân biệt `JustInTimeLoader` với `PrebuiltLoader` và báo cáo việc sử dụng một tập prebuilt loader.<sup>[[6]](#references)</sup>

```bash
DYLD_PRINT_SEARCHING=1 DYLD_PRINT_LOADERS=1 DYLD_PRINT_LIBRARIES=1 /path/to/binary 2>&1 | tee /tmp/dyld-search.log
```

Tìm dòng `LC_RPATH` xác định image cung cấp run path, sau đó đối chiếu các ứng viên `possible path(...)` với `found: dylib-from-disk`, `found: dylib-from-cache` hoặc thông báo từ chối. Đường dẫn ứng viên **không** chứng minh dylib đã được tải. Đường dẫn trên đĩa đầu tiên có thể sử dụng trước thư viện dự kiến là đường dẫn cần kiểm tra quyền ghi và [các hạn chế library-validation](./#library-validation).<sup>[[7]](#references)</sup>

Loader được dựng sẵn có thể dùng lại thông tin dependency đã ghi nhận thay vì lặp lại toàn bộ quá trình tìm kiếm đường dẫn. Vì vậy, kết quả tìm kiếm thưa thớt không phải bằng chứng cho thấy image không có dependency; hãy kiểm tra các load command bằng `otool -l` và đối chiếu danh sách thư viện.<sup>[[8]](#references)</sup> Các chẩn đoán này cũng cần quyền cho phép in biến của dyld, vì vậy target được bảo vệ có thể bỏ qua chúng hoàn toàn.<sup>[[2]](#references)</sup> Xem [Dylib Hijacking](./#dylib-hijacking) để biết các điều kiện tiên quyết khi thay thế thư viện.

### Khác

Một số switch bên dưới chỉ dành cho các bản dyld cũ hơn. Hãy kiểm tra xem phiên bản trên target có hỗ trợ hay không, thay vì mặc định rằng mọi biến vẫn hoạt động.<sup>[[2]](#references)[[9]](#references)</sup>

- `DYLD_BIND_AT_LAUNCH`: Các binding lazy được phân giải cùng với binding non-lazy
- `DYLD_DISABLE_PREFETCH`: Tắt pre-fetch nội dung \_\_DATA và \_\_LINKEDIT
- `DYLD_FORCE_FLAT_NAMESPACE`: Binding một cấp
- `DYLD_[FRAMEWORK/LIBRARY]_PATH | DYLD_FALLBACK_[FRAMEWORK/LIBRARY]_PATH | DYLD_VERSIONED_[FRAMEWORK/LIBRARY]_PATH`: Các đường dẫn phân giải
- `DYLD_INSERT_LIBRARIES`: Tải một thư viện cụ thể
- `DYLD_PRINT_TO_FILE`: Ghi thông tin debug của dyld vào một file
- `DYLD_PRINT_APIS`: In các lệnh gọi API của libdyld
- `DYLD_PRINT_APIS_APP`: In các lệnh gọi API của libdyld do main thực hiện
- `DYLD_PRINT_BINDINGS`: In các symbol khi được bind
- `DYLD_PRINT_WEAK_BINDINGS` (dyld2): In các binding của weak symbol
- `DYLD_PRINT_CODE_SIGNATURES`: In các thao tác đăng ký code signature
- `DYLD_PRINT_DOFS`: In các section định dạng object D-Trace khi được tải
- `DYLD_PRINT_ENV`: In các biến môi trường mà dyld nhìn thấy
- `DYLD_PRINT_INTERPOSING`: In các thao tác interposing
- `DYLD_PRINT_LIBRARIES`: In các thư viện được tải
- `DYLD_PRINT_OPTS`: In các tùy chọn tải
- `DYLD_PRINT_REBASINGS` (dyld2): In các thao tác rebase symbol
- `DYLD_PRINT_RPATHS` (dyld2): In các lần mở rộng `@rpath`
- `DYLD_PRINT_SEGMENTS`: In các ánh xạ của Mach-O segment
- `DYLD_PRINT_STATISTICS`: In thống kê thời gian
- `DYLD_PRINT_STATISTICS_DETAILS`: In thống kê thời gian chi tiết
- `DYLD_PRINT_WARNINGS`: In thông báo cảnh báo
- `DYLD_SHARED_CACHE_DIR`: Đường dẫn dùng cho shared library cache
- `DYLD_SHARED_REGION`: "use", "private", "avoid"
- `DYLD_USE_CLOSURES`: Bật closures

Có thể tìm thêm bằng lệnh tương tự như:

```bash
strings /usr/lib/dyld | grep "^DYLD_" | sort -u
```

Hoặc tải dự án dyld từ [https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz](https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz) và chạy bên trong thư mục:

```bash
find . -type f | xargs grep strcmp| grep key,\ \" | cut -d'"' -f2 | sort -u
```



## References

- [1] [dyld — `dyld/dyldMain.cpp` (đường dẫn khởi động tiến trình)](https://github.com/apple-oss-distributions/dyld/blob/main/dyld/dyldMain.cpp)
- [2] [dyld — `dyld/DyldProcessConfig.cpp` (cấu hình tiến trình/bảo mật)](https://github.com/apple-oss-distributions/dyld/blob/main/dyld/DyldProcessConfig.cpp)
- [3] [XNU — `bsd/kern/kern_exec.c` (phía kernel của `execve`, nạp dyld)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/kern_exec.c)
- [4] [dyld — `include/mach-o/dyld_images.h` (cấu trúc `dyld_all_image_infos`)](https://opensource.apple.com/source/dyld/dyld-852.2/include/mach-o/dyld_images.h.auto.html)
- [5] [fishhook — liên kết con trỏ symbol lazy và non-lazy](https://github.com/meta/fishhook)
- [6] [dyld(1) — chẩn đoán dynamic linker](https://github.com/apple-oss-distributions/dyld/blob/main/doc/man/man1/dyld.1)
- [7] [dyld — tìm kiếm đường dẫn thư viện lúc runtime](https://github.com/apple-oss-distributions/dyld/blob/main/dyld/Loader.cpp)
- [8] [dyld4 — trình nạp dựng sẵn và just-in-time](https://github.com/apple-oss-distributions/dyld/blob/main/doc/dyld4.md)
- [9] [dyld2 — tên biến chẩn đoán cũ](https://github.com/apple-oss-distributions/dyld/blob/dyld-852.2/src/dyld2.cpp)
{{#include ../../../../banners/hacktricks-training.md}}
