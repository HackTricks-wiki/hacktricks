# macOS GCD - Grand Central Dispatch

{{#include ../../banners/hacktricks-training.md}}

## 基本信息

**Grand Central Dispatch (GCD)**，也称为 **libdispatch** (`libdispatch.dyld`)，同时存在于 macOS 和 iOS 中。这是一项由 Apple 开发的技术，用于优化应用程序在多核硬件上对并发（多线程）执行的支持。<sup>[[4]](#references)</sup>

**GCD** 提供并管理 **FIFO 队列**，应用程序可以将以 **block 对象**形式存在的**任务提交**到这些队列中。提交到 dispatch 队列的 block 会在完全由系统管理的**线程池中执行**。GCD 会自动创建线程来执行 dispatch 队列中的任务，并调度这些任务在可用核心上运行。<sup>[[1]](#references)</sup>

> [!TIP]
> 总而言之，为了**并行**执行代码，进程可以将**代码 block 发送给 GCD**，由 GCD 负责执行。因此，进程不会创建新线程；**GCD 使用自己的线程池执行给定的代码**（该线程池可能会根据需要增加或减少）。

这对于成功管理并行执行非常有帮助，可以大幅减少进程创建的线程数量，并优化并行执行。这非常适合需要**高度并行性**的任务（brute-forcing？），或者不应阻塞主线程的任务：例如，iOS 上的主线程负责处理 UI 交互，因此任何可能导致应用卡顿的其他功能（搜索、访问 web、读取文件……）都会通过这种方式进行管理。

### Blocks

block 是一个**自包含的代码段**（类似于带参数并返回值的函数），还可以指定绑定变量。\
然而，在编译器层面 block 并不存在，它们是 `os_object`。每个对象由两个结构组成：

- **block literal**：
- 它以 **`isa`** 字段开始，该字段指向 block 的类：
- `NSConcreteGlobalBlock`（来自 `__DATA.__const` 的 block）
- `NSConcreteMallocBlock`（位于堆中的 block）
- `NSConcreateStackBlock`（位于栈中的 block）
- 它包含 **`flags`**（用于指示 block descriptor 中存在的字段）以及一些保留字节
- 要调用的函数指针
- 指向 block descriptor 的指针
- Block 导入的变量（如果有）
- **block descriptor**：其大小取决于存在的数据（如前面的 flags 所示）
- 它包含一些保留字节
- 其大小
- 通常会包含一个指向 Objective-C 风格签名的指针，用于确定参数所需的空间大小（flag `BLOCK_HAS_SIGNATURE`）
- 如果引用了变量，此 block 还会包含指向 copy helper（在开始时复制值）和 dispose helper（释放值）的指针。

### Queues

dispatch queue 是一个命名对象，用于按照 FIFO 顺序排列待执行的 block。<sup>[[3]](#references)</sup>

Block 会被放入队列中执行，而队列支持两种模式：`DISPATCH_QUEUE_SERIAL` 和 `DISPATCH_QUEUE_CONCURRENT`。当然，**serial** 队列**不会有 race condition** 问题，因为前一个 block 完成执行之前，下一个 block 不会执行。但**另一种队列可能存在此问题**。

默认队列：

- `.main-thread`：来自 `dispatch_get_main_queue()`
- `.libdispatch-manager`：GCD 的队列管理器
- `.root.libdispatch-manager`：GCD 的队列管理器
- `.root.maintenance-qos`：最低优先级任务
- `.root.maintenance-qos.overcommit`
- `.root.background-qos`：可用作 `DISPATCH_QUEUE_PRIORITY_BACKGROUND`
- `.root.background-qos.overcommit`
- `.root.utility-qos`：可用作 `DISPATCH_QUEUE_PRIORITY_NON_INTERACTIVE`
- `.root.utility-qos.overcommit`
- `.root.default-qos`：可用作 `DISPATCH_QUEUE_PRIORITY_DEFAULT`
- `.root.background-qos.overcommit`
- `.root.user-initiated-qos`：可用作 `DISPATCH_QUEUE_PRIORITY_HIGH`
- `.root.background-qos.overcommit`
- `.root.user-interactive-qos`：最高优先级
- `.root.background-qos.overcommit`

请注意，**在每个时间点由哪些线程处理哪些队列**是由系统决定的（多个线程可能处理同一个队列，或者同一个线程可能在某个时刻处理不同的队列）。

#### Attributtes

使用 **`dispatch_queue_create`** 创建队列时，第三个参数是 `dispatch_queue_attr_t`，通常为 `DISPATCH_QUEUE_SERIAL`（实际上是 NULL）或 `DISPATCH_QUEUE_CONCURRENT`。后者是指向 `dispatch_queue_attr_t` 结构的指针，可以用于控制队列的一些参数。

### Dispatch objects

libdispatch 使用多种对象，队列和 block 只是其中的两种。可以使用 `dispatch_object_create` 创建这些对象：<sup>[[1]](#references)[[2]](#references)</sup>

- `block`
- `data`：Data blocks
- `group`：Block 组
- `io`：异步 I/O 请求
- `mach`：Mach 端口
- `mach_msg`：Mach 消息
- `pthread_root_queue`：具有 pthread 线程池而非 workqueues 的队列
- `queue`
- `semaphore`
- `source`：事件源

## Objective-C

在 Objetive-C 中，有不同的函数可以将 block 发送出去并行执行：

- [**dispatch_async**](https://developer.apple.com/documentation/dispatch/1453057-dispatch_async)：提交一个 block，使其在 dispatch queue 上异步执行，并立即返回。
- [**dispatch_sync**](https://developer.apple.com/documentation/dispatch/1452870-dispatch_sync)：提交一个 block 对象执行，并在该 block 执行完成后返回。
- [**dispatch_once**](https://developer.apple.com/documentation/dispatch/1447169-dispatch_once)：在应用程序的整个生命周期内仅执行一次 block 对象。
- [**dispatch_async_and_wait**](https://developer.apple.com/documentation/dispatch/3191901-dispatch_async_and_wait)：提交一个 work item 执行，并仅在其执行完成后返回。不同于 [**`dispatch_sync`**](https://developer.apple.com/documentation/dispatch/1452870-dispatch_sync)，该函数在执行 block 时会遵循队列的所有属性。

这些函数需要以下参数：[**`dispatch_queue_t`**](https://developer.apple.com/documentation/dispatch/dispatch_queue_t) **`queue,`** [**`dispatch_block_t`**](https://developer.apple.com/documentation/dispatch/dispatch_block_t) **`block`**

这是 **Block 的结构体**：
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
以下是使用 **并行** 和 **`dispatch_async`** 的示例：
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

**`libswiftDispatch`** 是一个为最初使用 C 编写的 Grand Central Dispatch (GCD) framework 提供 **Swift bindings** 的 library。\
**`libswiftDispatch`** library 将 C GCD APIs 封装在更加 Swift 友好的 interface 中，让 Swift developers 使用 GCD 更加简单直观。

- **`DispatchQueue.global().sync{ ... }`**
- **`DispatchQueue.global().async{ ... }`**
- **`let onceToken = DispatchOnce(); onceToken.perform { ... }`**
- **`async await`**
- **`var (data, response) = await URLSession.shared.data(from: URL(string: "https://api.example.com/getData"))`**

**代码示例**：
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

以下 Frida 脚本可用于 **hook 多个 `dispatch`** 函数，并提取队列名称、backtrace 和 block：[**https://github.com/seemoo-lab/frida-scripts/blob/main/scripts/libdispatch.js**](https://github.com/seemoo-lab/frida-scripts/blob/main/scripts/libdispatch.js)。
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

目前 Ghidra 既无法理解 ObjectiveC **`dispatch_block_t`** 结构，也无法理解 **`swift_dispatch_block`** 结构。

因此，如果你希望它能够理解这些结构，只需**声明它们**：

<figure><img src="../../images/image (1160).png" alt="" width="563"><figcaption></figcaption></figure>

<figure><img src="../../images/image (1162).png" alt="" width="563"><figcaption></figcaption></figure>

<figure><img src="../../images/image (1163).png" alt="" width="563"><figcaption></figcaption></figure>

然后，在代码中找到它们被**使用**的位置：

> [!TIP]
> 注意所有对 "block" 的引用，以了解如何判断该结构体正在被使用。

<figure><img src="../../images/image (1164).png" alt="" width="563"><figcaption></figcaption></figure>

右键点击变量 -> Retype Variable，并在本例中选择 **`swift_dispatch_block`**：

<figure><img src="../../images/image (1165).png" alt="" width="563"><figcaption></figcaption></figure>

Ghidra 将自动重写所有内容：

<figure><img src="../../images/image (1166).png" alt="" width="563"><figcaption></figcaption></figure>

## References

- [1] [libdispatch — `src/queue.c` (queue/thread-pool implementation)](https://github.com/apple-oss-distributions/libdispatch/blob/main/src/queue.c)
- [2] [libdispatch — `src/source.c` (dispatch sources)](https://github.com/apple-oss-distributions/libdispatch/blob/main/src/source.c)
- [3] [libdispatch — `dispatch/queue.h` (public queue API)](https://github.com/apple-oss-distributions/libdispatch/blob/main/dispatch/queue.h)
- [4] [Apple Developer — Dispatch](https://developer.apple.com/documentation/dispatch)

{{#include ../../banners/hacktricks-training.md}}
