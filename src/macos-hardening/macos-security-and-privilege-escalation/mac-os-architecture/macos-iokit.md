# macOS IOKit

{{#include ../../../banners/hacktricks-training.md}}

## Thông tin cơ bản

I/O Kit là một **framework driver thiết bị** hướng đối tượng, mã nguồn mở trong kernel XNU, xử lý **driver thiết bị được tải động**. Framework này cho phép thêm mã mô-đun vào kernel ngay khi cần, hỗ trợ nhiều loại phần cứng.

Các driver IOKit về cơ bản sẽ **export các hàm từ kernel**. **Kiểu** tham số của các hàm này được **định nghĩa trước** và được xác minh. Hơn nữa, tương tự như XPC, IOKit chỉ là một lớp khác **nằm trên các Mach message**.

**Mã nguồn IOKit trong kernel XNU** được Apple công khai tại [https://github.com/apple-oss-distributions/xnu/tree/main/iokit](https://github.com/apple-oss-distributions/xnu/tree/main/iokit). Ngoài ra, các thành phần IOKit ở user space cũng có mã nguồn mở tại [https://github.com/opensource-apple/IOKitUser](https://github.com/opensource-apple/IOKitUser).

Tuy nhiên, **không có driver IOKit nào** có mã nguồn mở. Dù vậy, đôi khi một bản phát hành driver có thể đi kèm symbols giúp việc debug dễ dàng hơn. Xem cách [**lấy các driver extension từ firmware tại đây**](#ipsw)**.**

IOKit được viết bằng **C++**. Bạn có thể lấy các symbol C++ đã được giải mã tên bằng:

```bash
# Get demangled symbols
nm -C com.apple.driver.AppleJPEGDriver

# Demangled symbols from stdin
c++filt
__ZN16IOUserClient202222dispatchExternalMethodEjP31IOExternalMethodArgumentsOpaquePK28IOExternalMethodDispatch2022mP8OSObjectPv
IOUserClient2022::dispatchExternalMethod(unsigned int, IOExternalMethodArgumentsOpaque*, IOExternalMethodDispatch2022 const*, unsigned long, OSObject*, void*)
```

> [!CAUTION]
> Các **hàm được cung cấp** của IOKit có thể thực hiện **các bước kiểm tra bảo mật bổ sung** khi client cố gọi một hàm, nhưng lưu ý rằng các ứng dụng thường bị **sandbox** giới hạn về những hàm IOKit mà chúng có thể tương tác.

## Trình điều khiển

Trong macOS, chúng nằm trong:

- **`/System/Library/Extensions`**
  - Các tệp KEXT được tích hợp trong hệ điều hành OS X.
- **`/Library/Extensions`**
  - Các tệp KEXT được phần mềm bên thứ ba cài đặt.

Trong iOS, chúng nằm trong:

- **`/System/Library/Extensions`**

```bash
#Use kextstat to print the loaded drivers
kextstat
Executing: /usr/bin/kmutil showloaded
No variant specified, falling back to release
Index Refs Address            Size       Wired      Name (Version) UUID <Linked Against>
    1  142 0                  0          0          com.apple.kpi.bsd (20.5.0) 52A1E876-863E-38E3-AC80-09BBAB13B752 <>
    2   11 0                  0          0          com.apple.kpi.dsep (20.5.0) 52A1E876-863E-38E3-AC80-09BBAB13B752 <>
    3  170 0                  0          0          com.apple.kpi.iokit (20.5.0) 52A1E876-863E-38E3-AC80-09BBAB13B752 <>
    4    0 0                  0          0          com.apple.kpi.kasan (20.5.0) 52A1E876-863E-38E3-AC80-09BBAB13B752 <>
    5  175 0                  0          0          com.apple.kpi.libkern (20.5.0) 52A1E876-863E-38E3-AC80-09BBAB13B752 <>
    6  154 0                  0          0          com.apple.kpi.mach (20.5.0) 52A1E876-863E-38E3-AC80-09BBAB13B752 <>
    7   88 0                  0          0          com.apple.kpi.private (20.5.0) 52A1E876-863E-38E3-AC80-09BBAB13B752 <>
    8  106 0                  0          0          com.apple.kpi.unsupported (20.5.0) 52A1E876-863E-38E3-AC80-09BBAB13B752 <>
    9    2 0xffffff8003317000 0xe000     0xe000     com.apple.kec.Libm (1) 6C1342CC-1D74-3D0F-BC43-97D5AD38200A <5>
   10   12 0xffffff8003544000 0x92000    0x92000    com.apple.kec.corecrypto (11.1) F5F1255F-6552-3CF4-A9DB-D60EFDEB4A9A <8 7 6 5 3 1>
```

Cho đến số 9, các driver được liệt kê **được tải ở địa chỉ 0**. Điều này có nghĩa là chúng không phải driver thực sự mà là **một phần của kernel và không thể bị gỡ tải**.

Để tìm các extension cụ thể, bạn có thể dùng:

```bash
kextfind -bundle-id com.apple.iokit.IOReportFamily #Search by full bundle-id
kextfind -bundle-id -substring IOR #Search by substring in bundle-id
```

Để tải và gỡ tải các phần mở rộng kernel, hãy dùng:

```bash
kextload com.apple.iokit.IOReportFamily
kextunload com.apple.iokit.IOReportFamily
```

## IORegistry

**IORegistry** là một phần quan trọng của framework IOKit trên macOS và iOS, đóng vai trò như một cơ sở dữ liệu biểu diễn cấu hình và trạng thái phần cứng của hệ thống. Đây là **tập hợp phân cấp các đối tượng đại diện cho toàn bộ phần cứng và driver** được tải trên hệ thống, cùng các mối quan hệ giữa chúng.

Bạn có thể dùng CLI **`ioreg`** để xem IORegistry từ console (đặc biệt hữu ích trên iOS).

```bash
ioreg -l #List all
ioreg -w 0 #Not cut lines
ioreg -p <plane> #Check other plane
```

Bạn có thể tải **`IORegistryExplorer`** từ **Xcode Additional Tools** tại [**https://developer.apple.com/download/all/**](https://developer.apple.com/download/all/) và kiểm tra **macOS IORegistry** thông qua giao diện **đồ họa**.

<figure><img src="../../../images/image (1167).png" alt="" width="563"><figcaption></figcaption></figure>

Trong IORegistryExplorer, "planes" được dùng để sắp xếp và hiển thị mối quan hệ giữa các đối tượng khác nhau trong IORegistry. Mỗi plane đại diện cho một loại mối quan hệ cụ thể hoặc một chế độ xem cụ thể về cấu hình phần cứng và driver của hệ thống. Dưới đây là một số plane phổ biến bạn có thể gặp trong IORegistryExplorer:

1. **IOService Plane**: Đây là plane tổng quát nhất, hiển thị các đối tượng service đại diện cho driver và nub (kênh liên lạc giữa các driver). Plane này cho thấy mối quan hệ provider-client giữa các đối tượng đó.
2. **IODeviceTree Plane**: Plane này thể hiện các kết nối vật lý giữa các thiết bị khi chúng được kết nối với hệ thống. Nó thường được dùng để trực quan hóa hệ thống phân cấp của các thiết bị kết nối thông qua các bus như USB hoặc PCI.
3. **IOPower Plane**: Hiển thị các đối tượng và mối quan hệ của chúng liên quan đến quản lý nguồn. Plane này có thể cho thấy đối tượng nào đang ảnh hưởng đến trạng thái nguồn của các đối tượng khác, rất hữu ích khi gỡ lỗi các vấn đề liên quan đến nguồn.
4. **IOUSB Plane**: Tập trung cụ thể vào các thiết bị USB và mối quan hệ giữa chúng, hiển thị hệ thống phân cấp của các hub USB và thiết bị được kết nối.
5. **IOAudio Plane**: Plane này dùng để biểu diễn các thiết bị âm thanh và mối quan hệ giữa chúng trong hệ thống.
6. ...

## Ví dụ mã giao tiếp với driver

Đoạn mã sau kết nối với dịch vụ IOKit `YourServiceNameHere` và gọi selector 0:

- Trước tiên, nó gọi **`IOServiceMatching`** và **`IOServiceGetMatchingServices`** để lấy service.
- Sau đó, nó thiết lập kết nối bằng cách gọi **`IOServiceOpen`**.
- Cuối cùng, nó gọi một hàm bằng **`IOConnectCallScalarMethod`**, chỉ định selector 0 (selector là số được gán cho hàm bạn muốn gọi).

<details>
<summary>Ví dụ lời gọi từ user-space đến selector của driver</summary>

```objectivec
#import <Foundation/Foundation.h>
#import <IOKit/IOKitLib.h>

int main(int argc, const char * argv[]) {
    @autoreleasepool {
        // Get a reference to the service using its name
        CFMutableDictionaryRef matchingDict = IOServiceMatching("YourServiceNameHere");
        if (matchingDict == NULL) {
            NSLog(@"Failed to create matching dictionary");
            return -1;
        }

        // Obtain an iterator over all matching services
        io_iterator_t iter;
        kern_return_t kr = IOServiceGetMatchingServices(kIOMasterPortDefault, matchingDict, &iter);
        if (kr != KERN_SUCCESS) {
            NSLog(@"Failed to get matching services");
            return -1;
        }

        // Get a reference to the first service (assuming it exists)
        io_service_t service = IOIteratorNext(iter);
        if (!service) {
            NSLog(@"No matching service found");
            IOObjectRelease(iter);
            return -1;
        }

        // Open a connection to the service
        io_connect_t connect;
        kr = IOServiceOpen(service, mach_task_self(), 0, &connect);
        if (kr != KERN_SUCCESS) {
            NSLog(@"Failed to open service");
            IOObjectRelease(service);
            IOObjectRelease(iter);
            return -1;
        }

        // Call a method on the service
        // Assume the method has a selector of 0, and takes no arguments
        kr = IOConnectCallScalarMethod(connect, 0, NULL, 0, NULL, NULL);
        if (kr != KERN_SUCCESS) {
            NSLog(@"Failed to call method");
        }

        // Cleanup
        IOServiceClose(connect);
        IOObjectRelease(service);
        IOObjectRelease(iter);
    }
    return 0;
}
```

</details>

Có **những** hàm khác có thể dùng để gọi các hàm IOKit ngoài **`IOConnectCallScalarMethod`**, chẳng hạn **`IOConnectCallMethod`**, **`IOConnectCallStructMethod`**...

## Phân tích ngược entrypoint của driver

Ví dụ, bạn có thể lấy các hàm này từ một [**firmware image (ipsw)**](#ipsw). Sau đó, tải nó vào decompiler bạn yêu thích.

Bạn có thể bắt đầu dịch ngược hàm **`externalMethod`**, vì đây là hàm của driver nhận lời gọi và gọi hàm phù hợp:

<figure><img src="../../../images/image (1168).png" alt="" width="315"><figcaption></figcaption></figure>

<figure><img src="../../../images/image (1169).png" alt=""><figcaption></figcaption></figure>

Lời gọi tệ hại đã được giải mã tên đó có nghĩa là:

```cpp
IOUserClient2022::dispatchExternalMethod(unsigned int, IOExternalMethodArgumentsOpaque*, IOExternalMethodDispatch2022 const*, unsigned long, OSObject*, void*)
```

Lưu ý rằng trong định nghĩa trước đó, tham số **`self`** bị bỏ sót; định nghĩa chính xác sẽ là:

```cpp
IOUserClient2022::dispatchExternalMethod(self, unsigned int, IOExternalMethodArgumentsOpaque*, IOExternalMethodDispatch2022 const*, unsigned long, OSObject*, void*)
```

Trên thực tế, bạn có thể tìm thấy định nghĩa thực sự tại [https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/Kernel/IOUserClient.cpp#L6388](https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/Kernel/IOUserClient.cpp#L6388):

```cpp
IOUserClient2022::dispatchExternalMethod(uint32_t selector, IOExternalMethodArgumentsOpaque *arguments,
    const IOExternalMethodDispatch2022 dispatchArray[], size_t dispatchArrayCount,
    OSObject * target, void * reference)
```

Với thông tin này, bạn có thể viết lại Ctrl+Right -> `Edit function signature` và đặt các kiểu đã biết:

<figure><img src="../../../images/image (1174).png" alt=""><figcaption></figcaption></figure>

Mã decompiled mới sẽ trông như sau:

<figure><img src="../../../images/image (1175).png" alt=""><figcaption></figcaption></figure>

Ở bước tiếp theo, chúng ta cần định nghĩa struct **`IOExternalMethodDispatch2022`**. Struct này là mã nguồn mở tại [https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/IOKit/IOUserClient.h#L168-L176](https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/IOKit/IOUserClient.h#L168-L176), bạn có thể định nghĩa nó như sau:

<figure><img src="../../../images/image (1170).png" alt=""><figcaption></figcaption></figure>

Tiếp theo, tại `(IOExternalMethodDispatch2022 *)&sIOExternalMethodArray`, bạn sẽ thấy rất nhiều dữ liệu:

<figure><img src="../../../images/image (1176).png" alt="" width="563"><figcaption></figcaption></figure>

Đổi Data Type thành **`IOExternalMethodDispatch2022:`**

<figure><img src="../../../images/image (1177).png" alt="" width="375"><figcaption></figcaption></figure>

Sau khi thay đổi:

<figure><img src="../../../images/image (1179).png" alt="" width="563"><figcaption></figcaption></figure>

Và như bạn có thể thấy, ở đây có **mảng gồm 7 phần tử** (hãy kiểm tra mã decompiled cuối cùng). Hãy nhấp để tạo mảng gồm 7 phần tử:

<figure><img src="../../../images/image (1180).png" alt="" width="563"><figcaption></figcaption></figure>

Sau khi tạo mảng, bạn sẽ thấy tất cả các hàm được export:

<figure><img src="../../../images/image (1181).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Nếu bạn còn nhớ, để **gọi** một hàm **được export** từ user space, chúng ta không cần gọi tên hàm mà cần dùng **số selector**. Ở đây, bạn có thể thấy selector **0** là hàm **`initializeDecoder`**, selector **1** là **`startDecoder`**, selector **2** là **`initializeEncoder`**...

## Bề mặt tấn công IOKit gần đây (2023–2025)

- **Ghi lại thao tác gõ phím qua IOHIDFamily** – CVE-2024-27799 (14.5) cho thấy một client `IOHIDSystem` có quyền hạn lỏng lẻo có thể lấy các sự kiện HID ngay cả khi secure input được bật; hãy đảm bảo các handler `externalMethod` kiểm tra entitlements thay vì chỉ kiểm tra loại user-client.<sup>[[2]](#references)</sup>
- **Lỗi memory corruption trong IOGPUFamily** – CVE-2024-44197 và CVE-2025-24257 đã khắc phục lỗi ghi OOB có thể bị khai thác từ các ứng dụng sandbox khi chúng gửi dữ liệu có độ dài biến đổi không hợp lệ đến GPU user client; lỗi thường gặp là kiểm tra giới hạn kém đối với các đối số `IOConnectCallStructMethod`.<sup>[[1]](#references)</sup>
- **Theo dõi thao tác gõ phím kiểu cũ** – CVE-2023-42891 (14.2) xác nhận user client HID vẫn là vector thoát sandbox; hãy fuzz mọi driver cung cấp hàng đợi bàn phím/sự kiện.<sup>[[3]](#references)</sup>

### Mẹo phân loại nhanh và fuzzing

- Liệt kê tất cả external method của một user client từ userland để khởi tạo fuzzer:

```bash
# list selectors for a service
python3 - <<'PY'
from ioreg import IORegistry
svc = 'IOHIDSystem'
reg = IORegistry()
obj = reg.get_service(svc)
for sel, name in obj.external_methods():
    print(f"{sel:02d} {name}")
PY
```

- Khi reverse, hãy chú ý đến số lượng `IOExternalMethodDispatch2022`. Một mẫu lỗi phổ biến trong các CVE gần đây là `structureInputSize`/`structureOutputSize` không nhất quán với độ dài `copyin` thực tế, dẫn đến heap OOB trong `IOConnectCallStructMethod`.
- Khả năng truy cập từ sandbox vẫn phụ thuộc vào entitlements. Trước khi dành thời gian cho một mục tiêu, hãy kiểm tra xem client có được phép truy cập từ ứng dụng bên thứ ba hay không:

```bash
strings /System/Library/Extensions/IOHIDFamily.kext/Contents/MacOS/IOHIDFamily | \
  grep -E "^com\.apple\.(driver|private)"
```

- Với các lỗi GPU/iomfb, chỉ cần truyền các mảng quá lớn qua `IOConnectCallMethod` thường đã đủ để kích hoạt lỗi giới hạn. Harness tối giản (selector X) để kích hoạt nhầm lẫn kích thước:

```c
uint8_t buf[0x1000];
size_t outSz = sizeof(buf);
IOConnectCallStructMethod(conn, X, buf, sizeof(buf), buf, &outSz);
```



## DriverKit — Trình điều khiển không gian người dùng

### Kiến thức cơ bản về DriverKit

**DriverKit** là giải pháp thay thế kernel extension (kext) trong không gian người dùng của Apple, được giới thiệu trong macOS 10.15. Các binary DriverKit (bundle `.dext`) chạy dưới dạng tiến trình không gian người dùng nhưng giao tiếp trực tiếp với kernel thông qua giao diện IOKit có đặc quyền.<sup>[[4]](#references)</sup>

Các extension DriverKit quản lý phần cứng:
- Bộ điều khiển và thiết bị **USB**
- Thiết bị **Thunderbolt** / PCIe
- **HID** (bàn phím, chuột, tay cầm chơi game)
- Phần cứng **Audio**
- Giao diện **Networking**
- Thiết bị **Serial** và **Block Storage**

Không giống kext (yêu cầu khởi động khi SIP bị tắt hoặc phải được notarize), các extension DriverKit được cài đặt thông qua `SystemExtensions.framework` và chỉ cần **người dùng phê duyệt một lần**.<sup>[[5]](#references)</sup>

### Khám phá và liệt kê

```bash
# List all installed system extensions (includes DriverKit)
systemextensionsctl list

# Find all DriverKit extension bundles
find / -name "*.dext" -type d 2>/dev/null

# Check a binary's DriverKit entitlements
codesign -d --entitlements - /path/to/binary.dext/binary 2>&1 | grep driverkit

# Common DriverKit entitlements:
# com.apple.developer.driverkit                    — Base DriverKit
# com.apple.developer.driverkit.transport.usb      — USB device access
# com.apple.developer.driverkit.transport.hid      — HID device access
# com.apple.developer.driverkit.transport.pci      — PCIe device access
# com.apple.developer.driverkit.transport.serial   — Serial port access
# com.apple.developer.driverkit.family.networking  — Network interface
# com.apple.developer.driverkit.family.audio       — Audio device
```

### Ý nghĩa bảo mật

> [!WARNING]
> Các binary DriverKit có **kênh giao tiếp trực tiếp với kernel**. Gửi các message không hợp lệ qua kênh này có thể kích hoạt lỗ hổng kernel. Mỗi driver đăng ký các lớp user-client cụ thể, và các lệnh gọi `IOConnectCallMethod` không hợp lệ có thể gây hỏng bộ nhớ kernel.

**Bề mặt tấn công:**
1. **Fuzzing message Kernel IOKit** — Mỗi user-client của DriverKit cung cấp các selector có thể được gọi từ user space. Các đối số không hợp lệ có thể kích hoạt lỗi kernel.
2. **Giả mạo thiết bị USB** — Một binary USB DriverKit bị xâm phạm có thể giả dạng hồ sơ thiết bị USB độc hại (ví dụ: mô phỏng bàn phím để thực hiện HID injection).
3. **Tấn công DMA** — Các extension DriverKit cho PCIe/Thunderbolt có khả năng truy cập DMA vào bộ nhớ vật lý.
4. **Persistence** — Sau khi được cài đặt dưới dạng system extension, các binary DriverKit vẫn tồn tại qua các lần khởi động lại và cập nhật ứng dụng.

### Fuzzing IOKit User-Client của DriverKit

```bash
# Enumerate DriverKit user-client classes from entitlements
codesign -d --entitlements - /path/to/binary.dext/binary 2>&1 \
  | grep -A5 "com.apple.developer.driverkit.transport"

# List IOService matching for DriverKit drivers
ioreg -l | grep -i "UserClientClass" | sort -u

# Check if the driver's user-client is reachable from a sandboxed app
ioreg -c IOService -r -d 1 | grep -E '"IOClass"|"CFBundleIdentifier"' | head -40

# Minimal fuzzing harness for a DriverKit selector:
```

```c
#include <IOKit/IOKitLib.h>

io_connect_t conn;
// ... open connection to the DriverKit service ...

// Fuzz selector X with oversized struct input
uint8_t buf[0x2000];
memset(buf, 'A', sizeof(buf));
size_t outSz = sizeof(buf);
kern_return_t kr = IOConnectCallStructMethod(conn, X, buf, sizeof(buf), buf, &outSz);
// If the driver doesn't validate structureInputSize, this causes kernel OOB
```

### CVE của DriverKit

| CVE | Mô tả |
|---|---|
| CVE-2022-26766 | Lỗ hổng trong ngăn xếp USB của DriverKit — thực thi mã kernel |
| CVE-2021-30838 | Nhầm lẫn kiểu user-client của IOKit trong các driver đồ họa |
| CVE-2024-44197 | Ghi OOB trong IOGPUFamily thông qua các đối số DriverKit sai định dạng |

## References

- [1] [Bản cập nhật bảo mật của Apple – macOS Sequoia 15.1 / Sonoma 14.7.1 (IOGPUFamily)](https://support.apple.com/en-us/121564)
- [2] [Rapid7 – Tóm tắt IOHIDFamily CVE-2024-27799](https://www.rapid7.com/db/vulnerabilities/apple-osx-iohidfamily-cve-2024-27799/)
- [3] [Bản cập nhật bảo mật của Apple - macOS Sonoma 14.2 (CVE-2023-42891 IOKit)](https://support.apple.com/en-us/120879)
- [4] [Apple Developer — DriverKit](https://developer.apple.com/documentation/driverkit)
- [5] [Apple Developer — System Extensions](https://developer.apple.com/documentation/systemextensions)
{{#include ../../../banners/hacktricks-training.md}}
