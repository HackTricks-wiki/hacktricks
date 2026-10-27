# macOS GCD - Grand Central Dispatch

{{#include ../../banners/hacktricks-training.md}}

## Thông tin cơ bản

**Grand Central Dispatch (GCD),** còn được gọi là **libdispatch** (`libdispatch.dyld`), có trên cả macOS và iOS. Đây là công nghệ do Apple phát triển nhằm tối ưu hóa việc hỗ trợ ứng dụng thực thi đồng thời (đa luồng) trên phần cứng đa lõi.<sup>[[4]](#references)</sup>

**GCD** cung cấp và quản lý **các hàng đợi FIFO**, nơi ứng dụng có thể **gửi các tác vụ** dưới dạng **block object**. Các block được gửi đến dispatch queue sẽ **được thực thi trên một nhóm luồng** do hệ thống quản lý hoàn toàn. GCD tự động tạo luồng để thực thi các tác vụ trong dispatch queue và lên lịch chạy các tác vụ đó trên những lõi khả dụng.<sup>[[1]](#references)</sup>

> [!TIP]
> Tóm lại, để thực thi mã **song song**, các tiến trình có thể gửi **các block mã đến GCD**, nơi sẽ đảm nhiệm việc thực thi chúng. Do đó, các tiến trình không tạo luồng mới; **GCD thực thi mã được cung cấp bằng nhóm luồng của riêng nó** (có thể tăng hoặc giảm khi cần).

Điều này rất hữu ích để quản lý hiệu quả việc thực thi song song, giúp giảm đáng kể số lượng luồng mà tiến trình tạo ra và tối ưu hóa hoạt động thực thi song song. Cách này lý tưởng cho các tác vụ cần **mức độ song song cao** (brute-forcing?) hoặc không nên chặn luồng chính. Ví dụ: trên iOS, luồng chính xử lý các tương tác UI, vì vậy những chức năng khác có thể khiến ứng dụng bị treo (tìm kiếm, truy cập web, đọc tệp...) sẽ được quản lý theo cách này.

### Blocks

Một block là **một đoạn mã độc lập** (giống như một hàm có tham số và trả về giá trị) và cũng có thể chỉ định các biến được liên kết.\
Tuy nhiên, ở cấp trình biên dịch, block không tồn tại dưới dạng đó mà là các `os_object`. Mỗi object này được tạo thành từ hai cấu trúc:

- **block literal**:
  - Bắt đầu bằng trường **`isa`**, trỏ đến lớp của block:
    - `NSConcreteGlobalBlock` (các block từ `__DATA.__const`)
    - `NSConcreteMallocBlock` (các block trên heap)
    - `NSConcreateStackBlock` (các block trên stack)
  - Có **`flags`** (cho biết những trường nào có trong block descriptor) và một số byte dự trữ
  - Con trỏ hàm cần gọi
  - Con trỏ đến block descriptor
  - Các biến được block import (nếu có)
- **block descriptor**: Kích thước của nó phụ thuộc vào dữ liệu hiện có (như được chỉ ra trong các flag ở trên)
  - Có một số byte dự trữ
  - Kích thước của nó
  - Thường có một con trỏ đến chữ ký theo kiểu Objective-C để xác định cần bao nhiêu không gian cho các tham số (flag `BLOCK_HAS_SIGNATURE`)
  - Nếu có tham chiếu đến biến, block cũng có thể chứa con trỏ đến các hàm trợ giúp copy và dispose. Hàm trợ giúp copy chuyển các capture được giữ lại hoặc được quản lý theo cách khác khi block được sao chép; hàm trợ giúp dispose giải phóng trạng thái đó khi block đã sao chép bị hủy.

### Queues

Dispatch queue là một object có tên, cung cấp thứ tự FIFO cho các block được thực thi.<sup>[[3]](#references)</sup>

Các block được đưa vào queue để thực thi; queue hỗ trợ 2 chế độ: `DISPATCH_QUEUE_SERIAL` và `DISPATCH_QUEUE_CONCURRENT`. Dĩ nhiên, loại **serial** sẽ **không gặp vấn đề race condition**, vì một block sẽ không được thực thi cho đến khi block trước đó hoàn tất. Nhưng **loại queue còn lại có thể gặp vấn đề này**.

Các queue mặc định:

- `.main-thread`: Từ `dispatch_get_main_queue()`
- `.libdispatch-manager`: Trình quản lý queue của GCD
- `.root.libdispatch-manager`: Trình quản lý queue của GCD
- `.root.maintenance-qos`: Các tác vụ có độ ưu tiên thấp nhất
- `.root.maintenance-qos.overcommit`
- `.root.background-qos`: Khả dụng dưới dạng `DISPATCH_QUEUE_PRIORITY_BACKGROUND`
- `.root.background-qos.overcommit`
- `.root.utility-qos`: Khả dụng dưới dạng `DISPATCH_QUEUE_PRIORITY_NON_INTERACTIVE`
- `.root.utility-qos.overcommit`
- `.root.default-qos`: Khả dụng dưới dạng `DISPATCH_QUEUE_PRIORITY_DEFAULT`
- `.root.background-qos.overcommit`
- `.root.user-initiated-qos`: Khả dụng dưới dạng `DISPATCH_QUEUE_PRIORITY_HIGH`
- `.root.background-qos.overcommit`
- `.root.user-interactive-qos`: Độ ưu tiên cao nhất
- `.root.background-qos.overcommit`

Lưu ý rằng hệ thống sẽ quyết định **luồng nào xử lý queue nào vào từng thời điểm** (nhiều luồng có thể cùng xử lý một queue, hoặc cùng một luồng có thể xử lý các queue khác nhau vào một thời điểm nào đó).

#### Thuộc tính

Khi tạo queue bằng **`dispatch_queue_create`**, tham số thứ ba là `dispatch_queue_attr_t`, thường là `DISPATCH_QUEUE_SERIAL` (thực chất là NULL) hoặc `DISPATCH_QUEUE_CONCURRENT`, tức một con trỏ đến cấu trúc `dispatch_queue_attr_t` cho phép kiểm soát một số tham số của queue.

### Dispatch objects

libdispatch sử dụng nhiều loại object; queue và block chỉ là hai trong số đó. Các ghi chú reverse-engineering cũ có thể mô tả một quy trình tạo object chung là `dispatch_object_create`; tên này hữu ích khi nhận diện đầu ra decompiler hoặc ghi chú lịch sử, nhưng không phải là hàm tạo chung công khai trong các header libdispatch hiện nay. Mã công khai tạo từng object bằng API riêng theo loại, chẳng hạn như `dispatch_queue_create`, `dispatch_group_create`, `dispatch_semaphore_create` hoặc một biến thể của `dispatch_source_create`. Dispatch source được mô tả trong API công khai và được triển khai trong cây mã nguồn của libdispatch.<sup>[[1]](#references)</sup><sup>[[2]](#references)</sup><sup>[[3]](#references)</sup>

- `block`
- `data`: Các khối dữ liệu
- `group`: Nhóm block
- `io`: Các yêu cầu I/O bất đồng bộ
- `mach`: Các cổng Mach
- `mach_msg`: Các thông điệp Mach
- `pthread_root_queue`: Queue có nhóm luồng pthread, không dùng workqueue
- `queue`
- `semaphore`
- `source`: Nguồn sự kiện

## Objective-C

Objective-C cung cấp một số hàm để gửi block đi thực thi đồng thời:

- [**dispatch_async**](https://developer.apple.com/documentation/dispatch/1453057-dispatch_async): Gửi block để thực thi bất đồng bộ trên dispatch queue và trả về ngay lập tức.
- [**dispatch_sync**](https://developer.apple.com/documentation/dispatch/1452870-dispatch_sync): Gửi block object để thực thi và trả về sau khi block đó thực thi xong.
- [**dispatch_once**](https://developer.apple.com/documentation/dispatch/1447169-dispatch_once): Chỉ thực thi block object một lần trong suốt vòng đời của ứng dụng.
- [**dispatch_async_and_wait**](https://developer.apple.com/documentation/dispatch/3191901-dispatch_async_and_wait): Gửi work item để thực thi và chỉ trả về sau khi item đó thực thi xong. Khác với [**`dispatch_sync`**](https://developer.apple.com/documentation/dispatch/1452870-dispatch_sync), hàm này tuân theo tất cả thuộc tính của queue khi thực thi block.

Các hàm này nhận những tham số sau: [**`dispatch_queue_t`**](https://developer.apple.com/documentation/dispatch/dispatch_queue_t) **`queue,`** [**`dispatch_block_t`**](https://developer.apple.com/documentation/dispatch/dispatch_block_t) **`block`**

Đây là **cấu trúc của một Block**:

```c
struct Block {
   void *isa; // NSConcreteStackBlock,...
   int flags;
   int reserved;
   void *invoke;
   struct BlockDescriptor *descriptor;
   // captured variables go here
};
```

Và đây là một ví dụ sử dụng **tính song song** với **`dispatch_async`**:

```objectivec
#import <Foundation/Foundation.h>

// Define a block
void (^backgroundTask)(void) = ^{
    // Code to be executed in the background
    for (int i = 0; i < 10; i++) {
        NSLog(@"Background task %d", i);
        sleep(1);  // Simulate a long-running task
    }
};

int main(int argc, const char * argv[]) {
    @autoreleasepool {
        // Create a dispatch queue
        dispatch_queue_t backgroundQueue = dispatch_queue_create("com.example.backgroundQueue", NULL);

        // Submit the block to the queue for asynchronous execution
        dispatch_async(backgroundQueue, backgroundTask);

        // Continue with other work on the main queue or thread
        for (int i = 0; i < 10; i++) {
            NSLog(@"Main task %d", i);
            sleep(1);  // Simulate a long-running task
        }
    }
    return 0;
}
```

## Swift

**`libswiftDispatch`** là thư viện cung cấp **các binding Swift** cho framework Grand Central Dispatch (GCD), vốn được viết bằng C.\
Thư viện **`libswiftDispatch`** bao bọc các API GCD bằng C trong một giao diện thân thiện hơn với Swift, giúp các nhà phát triển Swift làm việc với GCD dễ dàng và trực quan hơn.

- **`DispatchQueue.global().sync{ ... }`**
- **`DispatchQueue.global().async{ ... }`**
- **`let onceToken = DispatchOnce(); onceToken.perform { ... }`**
- **`async await`**
  - **`var (data, response) = await URLSession.shared.data(from: URL(string: "https://api.example.com/getData"))`**

**Ví dụ code**:

```swift
import Foundation

// Define a closure (the Swift equivalent of a block)
let backgroundTask: () -> Void = {
    for i in 0..<10 {
        print("Background task \(i)")
        sleep(1)  // Simulate a long-running task
    }
}

// Entry point
autoreleasepool {
    // Create a dispatch queue
    let backgroundQueue = DispatchQueue(label: "com.example.backgroundQueue")

    // Submit the closure to the queue for asynchronous execution
    backgroundQueue.async(execute: backgroundTask)

    // Continue with other work on the main queue
    for i in 0..<10 {
        print("Main task \(i)")
        sleep(1)  // Simulate a long-running task
    }
}
```

## Frida

Có thể dùng script Frida sau để **hook vào một số hàm `dispatch`** và trích xuất tên hàng đợi, backtrace và block: [**https://github.com/seemoo-lab/frida-scripts/blob/main/scripts/libdispatch.js**](https://github.com/seemoo-lab/frida-scripts/blob/main/scripts/libdispatch.js)

```bash
frida -U <prog_name> -l libdispatch.js

dispatch_sync
Calling queue: com.apple.UIKit._UIReusePool.reuseSetAccess
Callback function: 0x19e3a6488 UIKitCore!__26-[_UIReusePool addObject:]_block_invoke
Backtrace:
0x19e3a6460 UIKitCore!-[_UIReusePool addObject:]
0x19e3a5db8 UIKitCore!-[UIGraphicsRenderer _enqueueContextForReuse:]
0x19e3a57fc UIKitCore!+[UIGraphicsRenderer _destroyCGContext:withRenderer:]
[...]
```

## Ghidra

Hiện tại Ghidra không hiểu cấu trúc ObjectiveC **`dispatch_block_t`** cũng như cấu trúc **`swift_dispatch_block`**.

Vì vậy, nếu muốn Ghidra hiểu chúng, bạn chỉ cần **khai báo chúng**:

<figure><img src="../../images/image (1160).png" alt="" width="563"><figcaption></figcaption></figure>

<figure><img src="../../images/image (1162).png" alt="" width="563"><figcaption></figcaption></figure>

<figure><img src="../../images/image (1163).png" alt="" width="563"><figcaption></figcaption></figure>

Sau đó, tìm một vị trí trong code nơi chúng được **sử dụng**:

> [!TIP]
> Lưu ý tất cả các tham chiếu đến "block" để hiểu cách xác định struct đang được sử dụng.

<figure><img src="../../images/image (1164).png" alt="" width="563"><figcaption></figcaption></figure>

Nhấp chuột phải vào biến -> Retype Variable rồi chọn **`swift_dispatch_block`** trong trường hợp này:

<figure><img src="../../images/image (1165).png" alt="" width="563"><figcaption></figcaption></figure>

Ghidra sẽ tự động viết lại mọi thứ:

<figure><img src="../../images/image (1166).png" alt="" width="563"><figcaption></figcaption></figure>

## References

- [1] [libdispatch — `src/queue.c` (triển khai hàng đợi/thread-pool)](https://github.com/apple-oss-distributions/libdispatch/blob/main/src/queue.c)
- [2] [libdispatch — `src/source.c` (dispatch sources)](https://github.com/apple-oss-distributions/libdispatch/blob/main/src/source.c)
- [3] [libdispatch — `dispatch/queue.h` (API hàng đợi công khai)](https://github.com/apple-oss-distributions/libdispatch/blob/main/dispatch/queue.h)
- [4] [Apple Developer — Dispatch](https://developer.apple.com/documentation/dispatch)
{{#include ../../banners/hacktricks-training.md}}
