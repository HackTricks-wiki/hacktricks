# macOS GCD - Grand Central Dispatch

{{#include ../../banners/hacktricks-training.md}}

## 基本信息

**Grand Central Dispatch (GCD)**，也称为 **libdispatch** (`libdispatch.dyld`)，在 macOS 和 iOS 中均可用。它是苹果公司开发的一项技术，旨在优化应用程序对多核硬件上并发（多线程）执行的支持。

**GCD** 提供并管理 **FIFO 队列**，您的应用程序可以将任务以 **块对象** 的形式 **提交** 到这些队列中。提交到调度队列的块会在系统完全管理的线程池上 **执行**。GCD 自动创建线程以执行调度队列中的任务，并安排这些任务在可用核心上运行。

> [!TIP]
> 总之，为了 **并行** 执行代码，进程可以将 **代码块发送到 GCD**，GCD 将负责它们的执行。因此，进程不会创建新线程；**GCD 使用其自己的线程池执行给定的代码**（线程池可能根据需要增加或减少）。

这对于成功管理并行执行非常有帮助，极大地减少了进程创建的线程数量，并优化了并行执行。这对于需要 **高度并行性**（暴力破解？）的任务或不应阻塞主线程的任务是理想的：例如，iOS 上的主线程处理 UI 交互，因此任何可能导致应用程序挂起的其他功能（搜索、访问网络、读取文件等）都是以这种方式管理的。

### 块

块是一个 **自包含的代码段**（像一个带参数返回值的函数），也可以指定绑定变量。\
然而，在编译器级别，块并不存在，它们是 `os_object`。每个这些对象由两个结构组成：

- **块字面量**：&#x20;
- 它以 **`isa`** 字段开始，指向块的类：
- `NSConcreteGlobalBlock`（来自 `__DATA.__const` 的块）
- `NSConcreteMallocBlock`（堆中的块）
- `NSConcreateStackBlock`（栈中的块）
- 它有 **`flags`**（指示块描述符中存在的字段）和一些保留字节
- 调用的函数指针
- 指向块描述符的指针
- 导入的块变量（如果有）
- **块描述符**：它的大小取决于存在的数据（如前面标志所示）
- 它有一些保留字节
- 它的大小
- 通常会有一个指向 Objective-C 风格签名的指针，以了解参数需要多少空间（标志 `BLOCK_HAS_SIGNATURE`）
- 如果引用了变量，则该块还将具有指向复制助手（在开始时复制值）和处置助手（释放它）的指针。

### 队列

调度队列是一个命名对象，提供块的 FIFO 执行顺序。

块被设置在队列中以供执行，这些队列支持两种模式：`DISPATCH_QUEUE_SERIAL` 和 `DISPATCH_QUEUE_CONCURRENT`。当然，**串行**队列 **不会有竞争条件** 问题，因为块不会在前一个块完成之前执行。但 **另一种类型的队列可能会有**。

默认队列：

- `.main-thread`: 来自 `dispatch_get_main_queue()`
- `.libdispatch-manager`: GCD 的队列管理器
- `.root.libdispatch-manager`: GCD 的队列管理器
- `.root.maintenance-qos`: 最低优先级任务
- `.root.maintenance-qos.overcommit`
- `.root.background-qos`: 可用作 `DISPATCH_QUEUE_PRIORITY_BACKGROUND`
- `.root.background-qos.overcommit`
- `.root.utility-qos`: 可用作 `DISPATCH_QUEUE_PRIORITY_NON_INTERACTIVE`
- `.root.utility-qos.overcommit`
- `.root.default-qos`: 可用作 `DISPATCH_QUEUE_PRIORITY_DEFAULT`
- `.root.background-qos.overcommit`
- `.root.user-initiated-qos`: 可用作 `DISPATCH_QUEUE_PRIORITY_HIGH`
- `.root.background-qos.overcommit`
- `.root.user-interactive-qos`: 最高优先级
- `.root.background-qos.overcommit`

请注意，系统将决定 **每次哪个线程处理哪个队列**（多个线程可能在同一队列中工作，或者同一线程可能在某些时候在不同队列中工作）

#### 属性

使用 **`dispatch_queue_create`** 创建队列时，第三个参数是 `dispatch_queue_attr_t`，通常是 `DISPATCH_QUEUE_SERIAL`（实际上是 NULL）或 `DISPATCH_QUEUE_CONCURRENT`，这是指向 `dispatch_queue_attr_t` 结构的指针，允许控制队列的一些参数。

### 调度对象

libdispatch 使用多个对象，队列和块只是其中两个。可以使用 `dispatch_object_create` 创建这些对象：

- `block`
- `data`: 数据块
- `group`: 块组
- `io`: 异步 I/O 请求
- `mach`: Mach 端口
- `mach_msg`: Mach 消息
- `pthread_root_queue`: 一个具有 pthread 线程池而不是工作队列的队列
- `queue`
- `semaphore`
- `source`: 事件源

## Objective-C

在 Objective-C 中，有不同的函数可以将块发送到并行执行：

- [**dispatch_async**](https://developer.apple.com/documentation/dispatch/1453057-dispatch_async): 提交一个块以在调度队列上异步执行，并立即返回。
- [**dispatch_sync**](https://developer.apple.com/documentation/dispatch/1452870-dispatch_sync): 提交一个块对象以执行，并在该块完成执行后返回。
- [**dispatch_once**](https://developer.apple.com/documentation/dispatch/1447169-dispatch_once): 在应用程序的生命周期内仅执行一次块对象。
- [**dispatch_async_and_wait**](https://developer.apple.com/documentation/dispatch/3191901-dispatch_async_and_wait): 提交一个工作项以执行，并仅在其完成执行后返回。与 [**`dispatch_sync`**](https://developer.apple.com/documentation/dispatch/1452870-dispatch_sync) 不同，此函数在执行块时尊重队列的所有属性。

这些函数期望这些参数：[**`dispatch_queue_t`**](https://developer.apple.com/documentation/dispatch/dispatch_queue_t) **`queue,`** [**`dispatch_block_t`**](https://developer.apple.com/documentation/dispatch/dispatch_block_t) **`block`**

这是 **块的结构**：
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
这是一个使用 **parallelism** 和 **`dispatch_async`** 的示例：
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

**`libswiftDispatch`** 是一个库，提供 **Swift 绑定** 到最初用 C 编写的 Grand Central Dispatch (GCD) 框架。\
**`libswiftDispatch`** 库将 C GCD API 封装在一个更适合 Swift 的接口中，使 Swift 开发者更容易和直观地使用 GCD。

- **`DispatchQueue.global().sync{ ... }`**
- **`DispatchQueue.global().async{ ... }`**
- **`let onceToken = DispatchOnce(); onceToken.perform { ... }`**
- **`async await`**
- **`var (data, response) = await URLSession.shared.data(from: URL(string: "https://api.example.com/getData"))`**

**代码示例**:
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

以下 Frida 脚本可用于 **hook 进入多个 `dispatch`** 函数并提取队列名称、回溯和块: [**https://github.com/seemoo-lab/frida-scripts/blob/main/scripts/libdispatch.js**](https://github.com/seemoo-lab/frida-scripts/blob/main/scripts/libdispatch.js)
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

目前 Ghidra 既不理解 ObjectiveC **`dispatch_block_t`** 结构，也不理解 **`swift_dispatch_block`** 结构。

所以如果你想让它理解这些结构，你可以**声明它们**：

<figure><img src="../../images/image (1160).png" alt="" width="563"><figcaption></figcaption></figure>

<figure><img src="../../images/image (1162).png" alt="" width="563"><figcaption></figcaption></figure>

<figure><img src="../../images/image (1163).png" alt="" width="563"><figcaption></figcaption></figure>

然后，找到代码中**使用**它们的地方：

> [!TIP]
> 注意所有提到“block”的引用，以了解你如何能够判断该结构正在被使用。

<figure><img src="../../images/image (1164).png" alt="" width="563"><figcaption></figcaption></figure>

右键单击变量 -> 重新输入变量，并在这种情况下选择 **`swift_dispatch_block`**：

<figure><img src="../../images/image (1165).png" alt="" width="563"><figcaption></figcaption></figure>

Ghidra 将自动重写所有内容：

<figure><img src="../../images/image (1166).png" alt="" width="563"><figcaption></figcaption></figure>

## References

- [**\*OS Internals, Volume I: User Mode. By Jonathan Levin**](https://www.amazon.com/MacOS-iOS-Internals-User-Mode/dp/099105556X)

{{#include ../../banners/hacktricks-training.md}}
